import { Body, Controller, Get, Post, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity'; 
import { CreateUserPasswordDto } from './dtos/create-user-password.dto';
import { LoginUserDto } from './dtos/login-user.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    async registerUserPassword(@Body() createUserPasswordDto: CreateUserPasswordDto){
        this.authService.registerUserPassword(createUserPasswordDto);
    }

    @Post('login')
    async loginUserPassword(@Body() loginUserDto: LoginUserDto){
        this.authService.loginUserPassword(loginUserDto);
    }

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleAuth(@Req() req) {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthRedirect(@Req() req) {
        const user = req.user as User; 

        if (!user) {
            throw new UnauthorizedException("User object not found after Google authentication"); 
        }

        const token = this.authService.getJwtToken({ id: user.id });
        const { password: _, ...userWithoutPassword } = user;

        return {
            message: 'User authenticated with Google successfully',
            user: userWithoutPassword,
            token,
        };
    }
}
