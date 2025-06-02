import { Body, Controller, Get, Post, Req, UnauthorizedException, UseGuards, Param, HttpCode, HttpStatus, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity'; 
import { CreateUserPasswordDto } from './dtos/create-user-password.dto';
import { LoginUserDto } from './dtos/login-user.dto';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
    ){}

    private setTokenCookie(res: Response, token: string) {
        const expiresInMs = 3 * 60 * 60 * 1000;
        res.cookie('access_token', token, {
            httpOnly: true,
            secure: this.configService.get<string>('NODE_ENV') === 'production',
            sameSite: 'lax',
            expires: new Date(Date.now() + expiresInMs),
            path: '/',
        });
    }

    @Post('register')
    @HttpCode(HttpStatus.OK)
    async registerUserPassword(@Body() createUserPasswordDto: CreateUserPasswordDto){
        return this.authService.registerUserPassword(createUserPasswordDto);
    }

    @Get('verify-account/:token')
    async verifyAccount(@Param('token') token: string, @Res({ passthrough: true }) res: Response) {
        const result = await this.authService.verifyAccount(token);
        if (result.jwtToken && result.user) {
            this.setTokenCookie(res, result.jwtToken);
        }
        const { jwtToken, ...responsePayload } = result;
        return responsePayload;
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async loginUserPassword(@Body() loginUserDto: LoginUserDto, @Res({ passthrough: true }) res: Response){
        const { user, token } = await this.authService.loginUserPassword(
            loginUserDto,
        );
        this.setTokenCookie(res, token);
        return { user };
    }

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleAuth(@Req() req) {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthRedirect(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const user = req.user as User; 

        if (!user) {
            throw new UnauthorizedException("User object not found after Google authentication"); 
        }

        const token = this.authService.getJwtToken({ id: user.id });
        this.setTokenCookie(res, token);
        const { password: _, ...userWithoutPassword } = user;

        return {
            message: 'User authenticated with Google successfully',
            user: userWithoutPassword,
            token,
        };
    }

    @Post('logout')
    @UseGuards(AuthGuard('jwt'))
    @HttpCode(HttpStatus.OK)
    async logout(@Res({ passthrough: true }) res: Response) {
        res.cookie('access_token', '', {
            httpOnly: true,
            secure: this.configService.get<string>('NODE_ENV') === 'production',
            sameSite: 'lax',
            expires: new Date(0),
            path: '/',
        });
        return { message: 'Logout successfully' };
    }
}
