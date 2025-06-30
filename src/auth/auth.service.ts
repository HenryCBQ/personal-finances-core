import { Injectable, BadRequestException, Logger, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '@moduleAuth/entities/user.entity';
import { JwtPayload } from '@moduleAuth/interfaces/jwt-payload.interface';
import { CreateUserPasswordDto } from '@moduleAuth/dtos/create-user-password.dto';
import { CreateUserGoogleDto } from '@moduleAuth/dtos/create-user-google.dto';
import { LoginUserDto } from './dtos/login-user.dto';
import { AuthUserResponse } from './interfaces';
import { EmailService } from '@moduleEmail/email.service';
import { ResetPasswordDto, ResetPasswordUrlDto } from './dtos/reset-password.dto';

@Injectable()
export class AuthService {
    private readonly logger = new Logger('AuthService');

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly jwtService: JwtService,
        private readonly emailService: EmailService,
    ){}

    async loginUserPassword(loginUserDto: LoginUserDto): Promise<{ user: AuthUserResponse, jwtToken: string }>
    {
        const { email, password } = loginUserDto;
        
        const user = await this.userRepository.findOne({
            where: { email: email.toLowerCase() },
            select: ['id', 'role', 'email', 'name', 'password', 'isActive', 'pictureUrl']
        })

        if (!user) {
            throw new UnauthorizedException('This account does not exist');
        }

        if(!user.password){
            throw new UnauthorizedException('User registered with Google. Please log in with your Google account');
        }

        if (! await bcrypt.compare(password, user.password)) {
            throw new UnauthorizedException('Invalid credentials');
        }

        if (!user.isActive) {
            throw new UnauthorizedException('User not active, please check your email for activation instructions');
        }

        const userResponse = this.getUserResponse(user);
        return {
            user: userResponse,
            jwtToken: this.getJwtToken({ id: user.id })
        };
    }

    async verifyAccount(token: string){
        const user = await this.userRepository.findOne({
            where: { verificationToken: token },
        });

        if (!user) {
            throw new NotFoundException('Invalid token');
        }

        if(user.isActive){
            throw new BadRequestException('User is already activated');
        }

        if(!user.verificationTokenExpiresAt || user.verificationTokenExpiresAt < new Date()){
            await this.userRepository.remove(user);
            throw new BadRequestException('The token has expired. Please register again to get a new one.');
        }

        user.isActive = true;
        user.verificationToken = null;
        user.verificationTokenExpiresAt = null;
        await this.userRepository.save(user);

        return {
            message: `${user.name}, your account was successfully activated, you can now log in.`
        };
    }

    async registerUserPassword(createUserPasswordDto: CreateUserPasswordDto){
        const userExist = await this.userRepository.findOne({
            where: { email: createUserPasswordDto.email.toLowerCase() }
        });

        if(userExist){
            throw new BadRequestException("User is already registered");
        }

        const { password, ...userData } = createUserPasswordDto;
        const { verificationToken, verificationTokenExpiresAt } = this._createTokenWithExpiration();
      
        const user = this.userRepository.create({
          ...userData,
          password: await bcrypt.hash(password, 10),
          verificationToken,
          verificationTokenExpiresAt
        });
      
        await this.userRepository.save(user);

        await this.emailService.sendAccountVerificationEmail(
            user.email,
            user.name,
            verificationToken,
        );
            
        return {
            message: 'Registration successful. Please check your email to activate your account',
        };
    }

    async validateOrCreateUserGoogle(createUserGoogleDto: CreateUserGoogleDto): Promise<AuthUserResponse> {
        const { email, name, googleId, pictureUrl } = createUserGoogleDto;

        let user = await this.userRepository.findOne({ where: { googleId } });

        if (user) {
            if (user.name !== name || user.pictureUrl !== pictureUrl) {
                user.name = name;
                user.pictureUrl = pictureUrl;
                await this.userRepository.save(user);
            }
            return user;
        }

        user = await this.userRepository.findOne({ where: { email } });

        if (user) {
            user.googleId = googleId;
            user.name = name; 
            user.pictureUrl = pictureUrl; 
            user.isActive = true; 
        } else {
            user = this.userRepository.create({
                email,
                name,
                googleId,
                pictureUrl,
                password: null, 
                isActive: true, 
            });
        }
            
        const userSaved = await this.userRepository.save(user);
        const userResponse: AuthUserResponse = this.getUserResponse(userSaved);
        return userResponse;
    }

    async sendResetPasswordUrl(resetPasswordUrl: ResetPasswordUrlDto) {
        const user = await this.userRepository.findOne({
            where: { email: resetPasswordUrl.email.toLowerCase() }
        });

        if(!user){
            throw new BadRequestException("User does not exist");
        }

        if(!user.isActive){
            throw new BadRequestException('User inactive');
        }
        
        const { verificationToken, verificationTokenExpiresAt } = this._createTokenWithExpiration();

        user.passwordResetToken = verificationToken;
        user.passwordResetExpiresAt = verificationTokenExpiresAt;
        await this.userRepository.save(user);

        await this.emailService.sendResetPasswordUrl(
            user.email,
            user.name,
            verificationToken,
        );
            
        return {
            message: 'An email has been sent with instructions to change your password.',
        };
    }

    async resetPassword(token: string, resetPassword: ResetPasswordDto) {
        const user = await this.userRepository.findOne({
            where: { passwordResetToken: token },
        });

        if (!user) {
            throw new NotFoundException('Invalid token');
        }

        if(!user.isActive){
            throw new BadRequestException('User inactive');
        }

        if(!user.passwordResetExpiresAt || user.passwordResetExpiresAt < new Date()){
            user.passwordResetToken = null;
            user.passwordResetExpiresAt = null;
            await this.userRepository.save(user);
            throw new BadRequestException('The token has expired');
        }

        user.password = bcrypt.hashSync(resetPassword.password, 10)
        user.passwordResetToken = null;
        user.passwordResetExpiresAt = null;
        await this.userRepository.save(user);

        return {
            message: `${user.name}, your password was changed successfully`
        };
    }

    public getUserResponse(user: User){
        const userResponse: AuthUserResponse = {
            id: user.id,
            role: user.role,
            email: user.email,
            name: user.name,
            pictureUrl: user.pictureUrl,
            isActive: user.isActive
        }
        return userResponse;
    }

    public getJwtToken(payload: JwtPayload){
        const token = this.jwtService.sign(payload);
        return token;
    }

    private _createTokenWithExpiration(hours: number = 24) {
        return {
            verificationToken: uuidv4(),
            verificationTokenExpiresAt: new Date(Date.now() + hours * 60 * 60 * 1000),
        };
    }
}
