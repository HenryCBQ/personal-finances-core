import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { CreateUserPasswordDto } from './dtos/create-user-password.dto';
import { LoginUserDto } from './dtos/login-user.dto';
import { ResetPasswordDto, ResetPasswordUrlDto } from './dtos/reset-password.dto';
import { Response } from 'express';
import { User } from './entities/user.entity';
import { UserRole } from './interfaces';

describe('AuthController', () => {
    let controller: AuthController;
    let authService: AuthService;

    const mockAuthService = {
        registerUserPassword: jest.fn(),
        verifyAccount: jest.fn(),
        loginUserPassword: jest.fn(),
        sendResetPasswordUrl: jest.fn(),
        resetPassword: jest.fn(),
        getJwtToken: jest.fn(),
        getUserResponse: jest.fn(),
    };

    const mockConfigService = {
        get: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AuthController],
            providers: [
                {
                    provide: AuthService,
                    useValue: mockAuthService,
                },
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
            ],
        }).compile();

        controller = module.get<AuthController>(AuthController);
        authService = module.get<AuthService>(AuthService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('registerUserPassword', () => {
        it('should call authService.registerUserPassword', async () => {
            const createUserDto: CreateUserPasswordDto = { email: 'test@example.com', password: 'password', name: 'Test' };
            await controller.registerUserPassword(createUserDto);
            expect(authService.registerUserPassword).toHaveBeenCalledWith(createUserDto);
        });
    });

    describe('verifyAccount', () => {
        it('should call authService.verifyAccount', async () => {
            const token = 'test_token';
            await controller.verifyAccount(token);
            expect(authService.verifyAccount).toHaveBeenCalledWith(token);
        });
    });

    describe('loginUserPassword', () => {
        it('should call authService.loginUserPassword and set cookie', async () => {
            const loginUserDto: LoginUserDto = { email: 'test@example.com', password: 'password' };
            const userResponse = { user: { id: 1, name: 'Test' }, jwtToken: 'test_token' };
            const res = { cookie: jest.fn() } as unknown as Response;

            mockAuthService.loginUserPassword.mockResolvedValue(userResponse);

            const result = await controller.loginUserPassword(loginUserDto, res);

            expect(authService.loginUserPassword).toHaveBeenCalledWith(loginUserDto);
            expect(res.cookie).toHaveBeenCalled();
            expect(result).toEqual({ user: userResponse.user });
        });
    });

    describe('sendResetPasswordUrl', () => {
        it('should call authService.sendResetPasswordUrl', async () => {
            const resetPasswordUrlDto: ResetPasswordUrlDto = { email: 'test@example.com' };
            await controller.sendResetPasswordUrl(resetPasswordUrlDto);
            expect(authService.sendResetPasswordUrl).toHaveBeenCalledWith(resetPasswordUrlDto);
        });
    });

    describe('resetPassword', () => {
        it('should call authService.resetPassword', async () => {
            const token = 'test_token';
            const resetPasswordDto: ResetPasswordDto = { password: 'newPassword' };
            await controller.resetPassword(token, resetPasswordDto);
            expect(authService.resetPassword).toHaveBeenCalledWith(token, resetPasswordDto);
        });
    });

    describe('checkAuthStatus', () => {
        it('should return user from authService.getUserResponse', () => {
            const user: User = { id: 1, name: 'Test', email: 'test@example.com', isActive: true, role: UserRole.USER, password: 'password', googleId: null, pictureUrl: null, verificationToken: null, verificationTokenExpiresAt: null, passwordResetToken: null, passwordResetExpiresAt: null, createdAt: new Date(), updatedAt: new Date(), lowercaseEmail: jest.fn() };
            const userResponse = { id: 1, name: 'Test' };
            mockAuthService.getUserResponse.mockReturnValue(userResponse);

            const result = controller.checkAuthStatus(user);
            expect(result).toEqual({ user: userResponse });
        });
    });

    describe('logout', () => {
        it('should clear the access_token cookie', async () => {
            const res = { cookie: jest.fn() } as unknown as Response;
            const result = await controller.logout(res);
            expect(res.cookie).toHaveBeenCalledWith('access_token', '', expect.any(Object));
            expect(result.message).toEqual('Logout successfully');
        });
    });
});
