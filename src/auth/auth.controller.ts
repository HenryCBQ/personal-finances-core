import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity'; 

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleAuth(@Req() req) {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthRedirect(@Req() req) {
        const user = req.user as User; 

        if (!user) {
            return { msg: 'Auth failed with Google' }; 
        }

        const token = this.authService.getJwtToken({ id: user.id });

        return {
            message: 'User authenticated with Google successfully',
            user,
            token,
        };
    }
}
