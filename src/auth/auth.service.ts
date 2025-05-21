import { Injectable, BadRequestException, InternalServerErrorException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '@moduleAuth/entities/user.entity';
import { JwtPayload } from '@moduleAuth/interfaces/jwt-payload.interface';
import { CreateUserPasswordDto } from '@moduleAuth/dtos/create-user-password.dto';
import { CreateUserGoogleDto } from '@moduleAuth/dtos/create-user-google.dto';

@Injectable()
export class AuthService {
    private readonly logger = new Logger('AuthService');

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly jwtService: JwtService
    ){}

    async createUserPassword(createUserPasswordDto: CreateUserPasswordDto){
        try {
            const { password, ...userData } = createUserPasswordDto;
      
            const user = this.userRepository.create({
              ...userData,
              password: bcrypt.hashSync(password, 10)
            });
      
            await this.userRepository.save(user);
            
            return {
              ...user,
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
          throw new BadRequestException(error.detail);
    
        this.logger.error(`Error in database: ${error.message}`); 
        throw new InternalServerErrorException('Please check server logs');
    }
}
