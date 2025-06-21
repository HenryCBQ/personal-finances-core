import { Injectable, BadRequestException, InternalServerErrorException, Logger, UnauthorizedException, NotFoundException } from '@nestjs/common';
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
            throw new UnauthorizedException('Esta cuenta no existe');
        }

        if(!user.password){
            throw new UnauthorizedException('Usuario registrado con Google. Inicie sesión con su cuenta de Google');
        }

        if (!bcrypt.compareSync(password, user.password)) {
            throw new UnauthorizedException('Credenciales inválidas');
        }

        if (!user.isActive) {
            throw new UnauthorizedException('Usuario no activo, consulte las instrucciones de activación en su correo');
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
            throw new NotFoundException('Token no válido');
        }

        if(user.isActive){
            throw new BadRequestException('El usuario ya está activado');
        }

        if(!user.verificationTokenExpiresAt || user.verificationTokenExpiresAt < new Date()){
            await this.userRepository.remove(user);
            throw new BadRequestException('El token expiró. Regístrate de nuevo para obtener otro.');
        }

        user.isActive = true;
        user.verificationToken = null;
        user.verificationTokenExpiresAt = null;
        await this.userRepository.save(user);

        return {
            message: `${user.name}, tú cuenta fue activada exitosamente, ya puedes iniciar sesión.`
        };
    }

    async registerUserPassword(createUserPasswordDto: CreateUserPasswordDto){
        const userExist = await this.userRepository.findOne({
            where: { email: createUserPasswordDto.email.toLowerCase() }
        });

        if(userExist){
            throw new BadRequestException("Usuario ya está registado");
        }

        const { password, ...userData } = createUserPasswordDto;
        const verificationToken = uuidv4();
        const verificationTokenExpiresAt = new Date(
            Date.now() + 24 * 60 * 60 * 1000,
        );
      
        const user = this.userRepository.create({
          ...userData,
          password: bcrypt.hashSync(password, 10),
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
            message: 'Registro exitoso. Revisa el correo electrónico para activar la cuenta',
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
}
