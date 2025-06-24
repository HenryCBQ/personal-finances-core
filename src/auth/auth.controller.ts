import { Body, Controller, Get, Post, Req, UnauthorizedException, UseGuards, Param, HttpCode, HttpStatus, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity'; 
import { CreateUserPasswordDto } from './dtos/create-user-password.dto';
import { LoginUserDto } from './dtos/login-user.dto';
import { GetUser } from './decorators/get-user.decorator';
import { ResetPasswordDto, ResetPasswordUrlDto } from './dtos/reset-password.dto';

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
        return await this.authService.registerUserPassword(createUserPasswordDto);
    }

    @Get('verify-account/:token')
    async verifyAccount(@Param('token') token: string) {
        return await this.authService.verifyAccount(token);
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async loginUserPassword(@Body() loginUserDto: LoginUserDto, @Res({ passthrough: true }) res: Response){
        const { user, jwtToken } = await this.authService.loginUserPassword(
            loginUserDto,
        );
        this.setTokenCookie(res, jwtToken);
        return { user };
    }

    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    async sendResetPasswordUrl(@Body() resetPasswordUrl: ResetPasswordUrlDto) {
        return await this.authService.sendResetPasswordUrl(resetPasswordUrl);
    }

    @Post('reset-password/:token')
    @HttpCode(HttpStatus.OK)
    async resetPassword(@Param('token') token: string, @Body() resetPassword: ResetPasswordDto) {
        return await this.authService.resetPassword(token, resetPassword);
    }

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleAuth(@Req() req) {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthRedirect(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const user = req.user as User; 
        const frontendLoginUrl = new URL(this.configService.get<string>('FRONTEND_URL'));

        if (!user) {
            throw new UnauthorizedException("User object not found after Google authentication"); 
        }

        const token = this.authService.getJwtToken({ id: user.id });
        this.setTokenCookie(res, token);
        
        const userResponse = this.authService.getUserResponse(user);
        frontendLoginUrl.pathname = '/';
        frontendLoginUrl.searchParams.set('user', JSON.stringify(userResponse));
        return res.redirect(frontendLoginUrl.toString());
    }

    @Get('profile')
    @UseGuards(AuthGuard('jwt'))
    checkAuthStatus( @GetUser() user: User) {
        return { user: this.authService.getUserResponse(user) };
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
