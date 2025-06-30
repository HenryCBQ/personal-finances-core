import { Test, TestingModule } from '@nestjs/testing';
import { EmailService } from './email.service';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

jest.mock('resend');

describe('EmailService', () => {
  let service: EmailService;
  let configService: ConfigService;
  let resend: Resend;

  const mockConfigService = {
    get: jest.fn(),
  };

  const mockResend = {
    emails: {
      send: jest.fn(),
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<EmailService>(EmailService);
    configService = module.get<ConfigService>(ConfigService);
    Resend.prototype.emails = mockResend.emails as any;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('sendAccountVerificationEmail', () => {
    it('should send a verification email', async () => {
      mockConfigService.get.mockReturnValue('test_key');
      mockResend.emails.send.mockResolvedValue({ data: { id: 'test_id' }, error: null });

      await service.sendAccountVerificationEmail('test@example.com', 'Test User', 'test_token');

      expect(mockResend.emails.send).toHaveBeenCalled();
    });
  });

  describe('sendResetPasswordUrl', () => {
    it('should send a reset password email', async () => {
      mockConfigService.get.mockReturnValue('test_key');
      mockResend.emails.send.mockResolvedValue({ data: { id: 'test_id' }, error: null });

      await service.sendResetPasswordUrl('test@example.com', 'Test User', 'test_token');

      expect(mockResend.emails.send).toHaveBeenCalled();
    });
  });
});
