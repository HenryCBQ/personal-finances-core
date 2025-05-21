import { IsEmail, IsString, MinLength } from "class-validator";

export class CreateUserGoogleDto {
    @IsString()
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(1)
    googleId: string;

    @IsString()
    @MinLength(1)
    name: string;

    @IsString()
    pictureUrl: string;
}