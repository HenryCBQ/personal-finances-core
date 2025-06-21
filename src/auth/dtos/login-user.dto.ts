import { IsEmail, IsString, MinLength, MaxLength } from "class-validator";

export class LoginUserDto {
    @IsString( { message: 'Correo electrónico inválido' } )
    @MinLength(6, { message: 'Correo electrónico inválido' })
    @MaxLength(60, { message: 'Correo electrónico inválido' })
    @IsEmail({}, { message: 'Correo electrónico inválido' })
    email: string

    @IsString()
    @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' } )
    @MaxLength(30, { message: 'La contraseña no puede tener más de 30 caracteres' })
    password: string;
}