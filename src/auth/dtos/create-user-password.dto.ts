import { IsEmail, IsString, Matches, MaxLength, MinLength } from "class-validator";

export class CreateUserPasswordDto {
    @IsString( { message: 'Correo electrónico inválido' } )
    @IsEmail( {}, { message: 'Correo electrónico inválido' } )
    @MinLength(6, { message: 'Correo electrónico inválido' } )
    @MaxLength(60, { message: 'Correo electrónico inválido' } )
    email: string;

    @IsString()
    @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres' } )
    @MaxLength(30, { message: 'La contraseña no puede tener más de 30 caracteres' } )
    @Matches(
        /(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/,{
            message: 'Contraseña debe tener al menos una letra mayúscula, una minúscula y un número'
        }
    )
    password: string;

    @IsString()
    @MinLength(3, { message: 'El nombre debe tener al menos 3 caracteres' })
    @MaxLength(60, { message: 'El nombre no puede tener más de 30 caracteres' }) 
    name: string;
}