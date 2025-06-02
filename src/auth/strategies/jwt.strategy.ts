import { PassportStrategy } from "@nestjs/passport";
import { InjectRepository } from "@nestjs/typeorm";
import { ConfigService } from "@nestjs/config";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { Repository } from "typeorm";
import { Strategy } from "passport-jwt";
import { Request } from 'express';
import { JwtPayload } from "@moduleAuth/interfaces/jwt-payload.interface";
import { User } from "@moduleAuth/entities/user.entity";

const cookieExtractor = (req: Request): string | null => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['access_token'];
    }
    return token;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        configService: ConfigService
    ){
        super({
            secretOrKey: configService.get('JWT_SECRET'),
            jwtFromRequest: cookieExtractor,
        });
    }

    async validate(payload: JwtPayload): Promise<User> {
        const { id } = payload;
        const user = await this.userRepository.findOneBy({ id });
        
        if(!user)
            throw new UnauthorizedException("Token not valid");

        if(!user.isActive)
            throw new UnauthorizedException("User is not active");

        const { password, verificationToken, verificationTokenExpiresAt, ...result } = user;
        return result as User;
    }
}