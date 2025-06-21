import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);
    private readonly resend: Resend;
    private readonly frontendVerificationUrl: string;

    constructor(private readonly configService: ConfigService) {
    const apiKey = this.configService.get<string>('RESEND_API_KEY');
    
    if (!apiKey) {
        this.logger.error('RESEND_API_KEY is not configured.');
        throw new Error('RESEND_API_KEY is not configured.');
    }

    this.resend = new Resend(apiKey);
    this.frontendVerificationUrl = this.configService.get<string>(
        'FRONTEND_VERIFICATION_URL',
    );
  }

  async sendAccountVerificationEmail(
    to: string,
    name: string,
    verificationToken: string,
  ): Promise<void> {
        const verificationLink = `${this.frontendVerificationUrl}/${verificationToken}`;
        const subject = 'Confirma tú cuenta de PersonalFinances';
        const htmlBody = `
                <h1>Bienvenido, <span class="math-inline">${name}</h1\>
                <p>Gracias por registrarte. Da click en el siguiente enlace para confirma tú cuenta: 
                    <a href="${verificationLink}">Confirmar</a>
                </p>
                <p>Si la cuenta no se confirma después de 24 horas el usuario tendrá que registrarse de nuevo.</p>
                <p>Si no fuiste tú, no es necesario ninguna acción.</p>
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
}
