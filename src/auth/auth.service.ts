import { Injectable, BadRequestException, InternalServerErrorException, Logger, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '@moduleAuth/entities/user.entity';
import { JwtPayload } from '@moduleAuth/interfaces/jwt-payload.interface';
import { CreateUserPasswordDto } from '@moduleAuth/dtos/create-user-password.dto';
import { CreateUserGoogleDto } from '@moduleAuth/dtos/create-user-google.dto';
import { LoginUserDto } from './dtos/login-user.dto';
import { IUserResponse } from './interfaces';

@Injectable()
export class AuthService {
    private readonly logger = new Logger('AuthService');

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly jwtService: JwtService
    ){}

    async loginUserPassword(loginUserDto: LoginUserDto): Promise<{ user: IUserResponse, token: string }>
    {
        const { email, password } = loginUserDto;
        
        const user = await this.userRepository.findOne({
            where: { email: email.toLowerCase() },
            select: ['id', 'email', 'name', 'password', 'isActive', 'role', 'pictureUrl', 'googleId']
        })

        if (!user) {
            throw new UnauthorizedException('Invalid credentials (email)');
        }

        if(!user.password){
            throw new UnauthorizedException('User registered with Google. Please use Google Sign-In or set a password');
        }

        if (!bcrypt.compareSync(password, user.password)) {
            throw new UnauthorizedException('Invalid credentials (password)');
        }

        if (!user.isActive) {
            throw new UnauthorizedException('User is not active');
        }

        const { password: _, ...userWithoutPassword } = user;

        return {
            user: userWithoutPassword,
            token: this.getJwtToken({ id: user.id })
        };
    }

    async registerUserPassword(createUserPasswordDto: CreateUserPasswordDto){
        try {
            const { password, ...userData } = createUserPasswordDto;
      
            const user = this.userRepository.create({
              ...userData,
              password: bcrypt.hashSync(password, 10)
            });
      
            await this.userRepository.save(user);

            const { password: _, ...userWithoutPassword } = user;
            
            return {
              ...userWithoutPassword,
              token: this.getJwtToken({ id: user.id })
            };
        } catch (error) {
            this.handleDBErrors(`Error in method createUserPassword: ${error.message}`);
        }
    }

    async validateOrCreateUserGoogle(createUserGoogleDto: CreateUserGoogleDto): Promise<User> {
        const { email, name, googleId, pictureUrl } = createUserGoogleDto;

        try {
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
            
            await this.userRepository.save(user);
            return user;

        } catch (error) {
            this.handleDBErrors(`Error in method validateOrCreateUserGoogle: ${error.message}`);
        }
    }

    public getJwtToken(payload: JwtPayload){
        const token = this.jwtService.sign(payload);
        return token;
    }

    private handleDBErrors(error: any): never {
        if(error.code === '23505')
          throw new BadRequestException(error.detail.includes('email') ? 'Email already exists' : error.detail);
    
        this.logger.error(`Error message: ${error.message}`); 
        throw new InternalServerErrorException('Unexpected error, please check server logs');
    }
}
