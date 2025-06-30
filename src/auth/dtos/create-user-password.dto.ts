import { IsEmail, IsString, Matches, MaxLength, MinLength } from "class-validator";

export class CreateUserPasswordDto {
    @IsString( { message: 'Invalid email' } )
    @IsEmail( {}, { message: 'Invalid email' } )
    @MinLength(6, { message: 'Invalid email' } )
    @MaxLength(60, { message: 'Invalid email' } )
    email: string;

    @IsString()
    @MinLength(8, { message: 'Password must be at least 8 characters long' } )
    @MaxLength(30, { message: 'Password cannot be longer than 30 characters' } )
    @Matches(
        /(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/,{
            message: 'Password must have at least one uppercase letter, one lowercase letter, and one number'
        }
    )
    password: string;

    @IsString()
    @MinLength(3, { message: 'Name must be at least 3 characters long' })
    @MaxLength(60, { message: 'Name cannot be longer than 30 characters' }) 
    name: string;
}