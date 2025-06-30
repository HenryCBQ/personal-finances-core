
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { EmailService } from '../email/email.service';
import { Repository } from 'typeorm';
import { CreateUserPasswordDto } from './dtos/create-user-password.dto';
import { LoginUserDto } from './dtos/login-user.dto';
import { ResetPasswordDto, ResetPasswordUrlDto } from './dtos/reset-password.dto';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UserRole } from './interfaces';

jest.mock('bcrypt');
jest.mock('uuid');

describe('AuthService', () => {
    let service: AuthService;
    let userRepository: Repository<User>;
    let jwtService: JwtService;
    let emailService: EmailService;

    const mockUserRepository = {
        findOne: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
        remove: jest.fn(),
    };

    const mockJwtService = {
        sign: jest.fn(),
    };

    const mockEmailService = {
        sendAccountVerificationEmail: jest.fn(),
        sendResetPasswordUrl: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                {
                    provide: getRepositoryToken(User),
                    useValue: mockUserRepository,
                },
                {
                    provide: JwtService,
                    useValue: mockJwtService,
                },
                {
                    provide: EmailService,
                    useValue: mockEmailService,
                },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
        userRepository = module.get<Repository<User>>(getRepositoryToken(User));
        jwtService = module.get<JwtService>(JwtService);
        emailService = module.get<EmailService>(EmailService);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('loginUserPassword', () => {
        it('should return user and token on successful login', async () => {
            const loginUserDto: LoginUserDto = { email: 'test@example.com', password: 'password' };
            const user = { id: 1, email: 'test@example.com', password: 'hashedpassword', isActive: true, name: 'Test User', role: UserRole.USER, pictureUrl: '' };
            const token = 'test_token';

            mockUserRepository.findOne.mockResolvedValue(user);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            mockJwtService.sign.mockReturnValue(token);

            const result = await service.loginUserPassword(loginUserDto);

            expect(result.user.email).toEqual(user.email);
            expect(result.jwtToken).toEqual(token);
        });

        it('should throw UnauthorizedException if user does not exist', async () => {
            const loginUserDto: LoginUserDto = { email: 'test@example.com', password: 'password' };
            mockUserRepository.findOne.mockResolvedValue(null);
            await expect(service.loginUserPassword(loginUserDto)).rejects.toThrow(UnauthorizedException);
        });

        it('should throw UnauthorizedException for invalid credentials', async () => {
            const loginUserDto: LoginUserDto = { email: 'test@example.com', password: 'wrongpassword' };
            const user = { id: 1, email: 'test@example.com', password: 'hashedpassword', isActive: true, name: 'Test User', role: UserRole.USER, pictureUrl: '' };
            mockUserRepository.findOne.mockResolvedValue(user);
            (bcrypt.compare as jest.Mock).mockResolvedValue(false);
            await expect(service.loginUserPassword(loginUserDto)).rejects.toThrow(UnauthorizedException);
        });

        it('should throw UnauthorizedException if user is not active', async () => {
            const loginUserDto: LoginUserDto = { email: 'test@example.com', password: 'password' };
            const user = { id: 1, email: 'test@example.com', password: 'hashedpassword', isActive: false, name: 'Test User', role: UserRole.USER, pictureUrl: '' };
            mockUserRepository.findOne.mockResolvedValue(user);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            await expect(service.loginUserPassword(loginUserDto)).rejects.toThrow(UnauthorizedException);
        });
    });

    describe('registerUserPassword', () => {
        it('should successfully register a user', async () => {
            const createUserDto: CreateUserPasswordDto = { email: 'test@example.com', password: 'password', name: 'Test' };
            const hashedPassword = 'hashedpassword';
            const verificationToken = 'test_token';
            const verificationTokenExpiresAt = new Date();

            mockUserRepository.findOne.mockResolvedValue(null);
            (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);
            (uuidv4 as jest.Mock).mockReturnValue(verificationToken);
            jest.spyOn(service as any, '_createTokenWithExpiration').mockReturnValue({ verificationToken, verificationTokenExpiresAt });
            mockUserRepository.create.mockReturnValue({ ...createUserDto, password: hashedPassword, verificationToken, verificationTokenExpiresAt });
            mockUserRepository.save.mockResolvedValue(undefined);
            mockEmailService.sendAccountVerificationEmail.mockResolvedValue(undefined);

            const result = await service.registerUserPassword(createUserDto);
            expect(result.message).toEqual('Registration successful. Please check your email to activate your account');
        });

        it('should throw BadRequestException if user already exists', async () => {
            const createUserDto: CreateUserPasswordDto = { email: 'test@example.com', password: 'password', name: 'Test' };
            mockUserRepository.findOne.mockResolvedValue({ id: 1, email: 'test@example.com' });
            await expect(service.registerUserPassword(createUserDto)).rejects.toThrow(BadRequestException);
        });
    });

    describe('verifyAccount', () => {
        it('should successfully verify an account', async () => {
            const token = 'valid_token';
            const user = {
                name: 'Test User',
                isActive: false,
                verificationToken: token,
                verificationTokenExpiresAt: new Date(Date.now() + 3600000),
                save: jest.fn().mockResolvedValue(true),
            };
            mockUserRepository.findOne.mockResolvedValue(user);

            const result = await service.verifyAccount(token);
            expect(result.message).toContain('your account was successfully activated');
            expect(user.isActive).toBe(true);
        });

        it('should throw NotFoundException for an invalid token', async () => {
            const token = 'invalid_token';
            mockUserRepository.findOne.mockResolvedValue(null);
            await expect(service.verifyAccount(token)).rejects.toThrow(NotFoundException);
        });

        it('should throw BadRequestException if the user is already active', async () => {
            const token = 'valid_token';
            const user = { isActive: true };
            mockUserRepository.findOne.mockResolvedValue(user);
            await expect(service.verifyAccount(token)).rejects.toThrow(BadRequestException);
        });

        it('should throw BadRequestException if the token has expired', async () => {
            const token = 'expired_token';
            const user = {
                isActive: false,
                verificationToken: token,
                verificationTokenExpiresAt: new Date(Date.now() - 3600000),
            };
            mockUserRepository.findOne.mockResolvedValue(user);
            await expect(service.verifyAccount(token)).rejects.toThrow(BadRequestException);
        });
    });

    describe('sendResetPasswordUrl', () => {
        it('should send a reset password email', async () => {
            const resetPasswordUrlDto: ResetPasswordUrlDto = { email: 'test@example.com' };
            const user = {
                email: 'test@example.com',
                name: 'Test User',
                isActive: true,
                save: jest.fn().mockResolvedValue(true),
            };
            const verificationToken = 'reset_token';
            const verificationTokenExpiresAt = new Date();

            mockUserRepository.findOne.mockResolvedValue(user);
            jest.spyOn(service as any, '_createTokenWithExpiration').mockReturnValue({ verificationToken, verificationTokenExpiresAt });
            mockEmailService.sendResetPasswordUrl.mockResolvedValue(undefined);

            const result = await service.sendResetPasswordUrl(resetPasswordUrlDto);
            expect(result.message).toContain('An email has been sent');
        });

        it('should throw BadRequestException if user does not exist', async () => {
            const resetPasswordUrlDto: ResetPasswordUrlDto = { email: 'test@example.com' };
            mockUserRepository.findOne.mockResolvedValue(null);
            await expect(service.sendResetPasswordUrl(resetPasswordUrlDto)).rejects.toThrow(BadRequestException);
        });

        it('should throw BadRequestException if user is inactive', async () => {
            const resetPasswordUrlDto: ResetPasswordUrlDto = { email: 'test@example.com' };
            const user = { isActive: false };
            mockUserRepository.findOne.mockResolvedValue(user);
            await expect(service.sendResetPasswordUrl(resetPasswordUrlDto)).rejects.toThrow(BadRequestException);
        });
    });

    describe('resetPassword', () => {
        it('should successfully reset a password', async () => {
            const token = 'valid_token';
            const resetPasswordDto: ResetPasswordDto = { password: 'newPassword' };
            const user = {
                name: 'Test User',
                isActive: true,
                passwordResetToken: token,
                passwordResetExpiresAt: new Date(Date.now() + 3600000),
                save: jest.fn().mockResolvedValue(true),
            };
            const hashedPassword = 'hashedNewPassword';

            mockUserRepository.findOne.mockResolvedValue(user);
            (bcrypt.hashSync as jest.Mock).mockReturnValue(hashedPassword);

            const result = await service.resetPassword(token, resetPasswordDto);
            expect(result.message).toContain('your password was changed successfully');
            expect(user.password).toEqual(hashedPassword);
        });

        it('should throw NotFoundException for an invalid token', async () => {
            const token = 'invalid_token';
            const resetPasswordDto: ResetPasswordDto = { password: 'newPassword' };
            mockUserRepository.findOne.mockResolvedValue(null);
            await expect(service.resetPassword(token, resetPasswordDto)).rejects.toThrow(NotFoundException);
        });

        it('should throw BadRequestException if the token has expired', async () => {
            const token = 'expired_token';
            const resetPasswordDto: ResetPasswordDto = { password: 'newPassword' };
            const user = {
                isActive: true,
                passwordResetToken: token,
                passwordResetExpiresAt: new Date(Date.now() - 3600000),
                save: jest.fn().mockResolvedValue(true),
            };
            mockUserRepository.findOne.mockResolvedValue(user);
            await expect(service.resetPassword(token, resetPasswordDto)).rejects.toThrow(BadRequestException);
        });
    });
});
