import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);
    private readonly resend: Resend;
    private readonly frontendVerificationUrl: string;
    private readonly apiBaseUrl: string;

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

    this.apiBaseUrl = this.configService.get<string>('API_BASE_URL');
  }

  async sendAccountVerificationEmail(
    to: string,
    name: string,
    verificationToken: string,
  ): Promise<void> {
    const verificationLink = `<span class="math-inline">\{this\.apiBaseUrl\}/auth/verify\-account/</span>{verificationToken}`;
    const subject = 'Confirma tú cuenta de Personal Finances';
    const htmlBody = `
            <h1>Bienvenido, <span class="math-inline">\{name\}\!</h1\>
            <p>Gracias por registrarte. Por favor da click en el enlace para confirma tú cuenta:</p>
            <a href="{verificationLink}">Confirmar mi cuente</a>
            <p>Esta URL expira en 24 horas.</p>
            <p>Si no fuiste tú el que creó esta cuenta no necesitas ninguna acción.</p>
        `; 
    const textBody = `
        Bienvenido, ${name}! Gracias por registrarte. Por favor da click en el enlace para confirma tú cuenta: ${verificationLink} Esta URL expira en 24 horas. Si no fuiste tú el que creó esta cuenta no necesitas ninguna acción.
    `;
    
    try {
        const { data, error } = await this.resend.emails.send({
            from: 'Personal Finances App <onboarding@resend.dev>', // Reemplaza con tu dominio verificado en Resend
            to: [to],
            subject: subject,
            html: htmlBody,
            text: textBody,
        });

        if (error) {
            this.logger.error(`Error sending verification email to ${to}:`, error.message);
            throw new Error(`Could not send verification email: ${error.message}`);
        }

        this.logger.log(`Verification email sent successfully to ${to}. Message ID: ${data?.id}`);
        } catch (error) {
            this.logger.error(`Failed to send verification email to ${to}`, error.stack);
            throw error; // Re-throw para que el servicio de autenticación pueda manejarlo
        }
    }
}
