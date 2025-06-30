import { IsEmail, IsString, MinLength, MaxLength, Matches } from "class-validator";

export class ResetPasswordUrlDto {
    @IsString( { message: 'Invalid email' } )
    @MinLength(6, { message: 'Invalid email' })
    @MaxLength(60, { message: 'Invalid email' })
    @IsEmail({}, { message: 'Invalid email' })
    email: string
}

export class ResetPasswordDto {
    @IsString()
    @MinLength(8, { message: 'Password must be at least 8 characters long' } )
    @MaxLength(30, { message: 'Password cannot be longer than 30 characters' })
    @Matches(
        /(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/,{
            message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
        }
    )
    password: string;
}