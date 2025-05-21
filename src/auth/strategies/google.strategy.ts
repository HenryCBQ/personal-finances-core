import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback, Profile } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';
import { CreateUserGoogleDto } from '../dtos/create-user-google.dto';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ) {
      const { id, name, emails, photos } = profile;
      
      if (!emails || emails.length === 0) {
        return done(new Error('Not found email in Google profile'), null);
      }

      const googleUserDto: CreateUserGoogleDto = {
        googleId: id,
        email: emails[0].value,
        name: name ? `${name.givenName || ''} ${name.familyName || ''}`.trim() : 'User Google',
        pictureUrl: photos && photos.length > 0 ? photos[0].value : null,
      };

      const user = await this.authService.validateOrCreateUserGoogle(googleUserDto);
      done(null, user);
    }
}
