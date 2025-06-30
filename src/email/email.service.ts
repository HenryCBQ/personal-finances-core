import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);
    private readonly resend: Resend;
    private readonly frontendUrl: string;

    constructor(private readonly configService: ConfigService) {
        const apiKey = this.configService.get<string>('RESEND_API_KEY');
        
        if (!apiKey) {
            this.logger.error('RESEND_API_KEY is not configured.');
            throw new Error('RESEND_API_KEY is not configured.');
        }

        this.resend = new Resend(apiKey);
        this.frontendUrl = this.configService.get<string>(
            'FRONTEND_URL',
        );
    }

  async sendAccountVerificationEmail(
    to: string,
    name: string,
    verificationToken: string,
  ): Promise<void> {
        const verificationLink = `${this.frontendUrl}/auth/verify-account/${verificationToken}`;
        const subject = 'Confirm your PersonalFinances account';
        const htmlBody = `
                <h1>Welcome, <span>${name}</span></h1>
                <p>Thanks for signing up. Click the link below to confirm your account:
                    <a href="${verificationLink}">Confirm</a>
                </p>
                <p>If the account is not confirmed after 24 hours, the user will have to register again.</p>
                <p>If it wasn\'t you, no action is necessary.</p>
            `;
    
        try {
            const { data, error } = await this.resend.emails.send({
                from: 'Personal Finances App <onboarding@resend.dev>',
                to: [to],
                subject: subject,
                html: htmlBody
            });

            if (error) {
                this.logger.error(`Error sending verification email to ${to}:`, error.message);
            }

            this.logger.log(`Verification email sent successfully to ${to}. Message ID: ${data?.id}`);
        } catch (error) {
            this.logger.error(`Failed to send verification email to ${to}`, error.message);
        }
    }

    async sendResetPasswordUrl(
        to: string,
        name: string,
        verificationToken: string,
    ): Promise<void> {
        const resetPasswordLink = `${this.frontendUrl}/auth/reset-password/${verificationToken}`;
        const subject = 'PersonalFinances password change request';
        const htmlBody = `
                <h1>Hello, <span>${name}</span></h1>
                <p>You have requested to change your password. Click on the following link to change it: 
                    <a href="${resetPasswordLink}">Change password</a>
                </p>
                <p>The URL expires in 24 hours.</p>
            `;
    
        try {
            const { data, error } = await this.resend.emails.send({
                from: 'Personal Finances App <onboarding@resend.dev>',
                to: [to],
                subject: subject,
                html: htmlBody
            });

            if (error) {
                this.logger.error(`Error sending reset password email to ${to}:`, error.message);
            }

            this.logger.log(`Reset password email sent successfully to ${to}. Message ID: ${data?.id}`);
        } catch (error) {
            this.logger.error(`Failed to send reset password email to ${to}`, error.message);
        }
    }
}
