import { IsNotEmpty, IsEmail, MinLength, Matches, IsOptional, IsString } from 'class-validator';

export class RegisterDto {
    @IsNotEmpty({ message: 'Company is required' })
    company: string;

    @IsNotEmpty({ message: 'First name is required' })
    @IsString({ message: 'First name must be a string' })
    firstName: string;

    @IsNotEmpty({ message: 'Last name is required' })
    @IsString({ message: 'Last name must be a string' })
    lastName: string;

    @IsNotEmpty({ message: 'Username is required' })
    @MinLength(4, { message: 'Username must be at least 4 characters' })
    username: string;

    @IsNotEmpty({ message: 'Email is required' })
    @IsEmail({}, { message: 'Invalid email format' })
    email: string;

    @IsOptional()
    @Matches(/^\+?[0-9]{9,15}$/, { message: 'Invalid phone number' })
    phone?: string;

    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(8, { message: 'Password must be at least 8 characters' })
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#._-])[A-Za-z\d@$!%*?&#._-]{8,}$/, {
        message: 'Password must contain at least 8 characters, a combination of upper, lower case, number and least one special character',
    })
    password: string;

    @IsNotEmpty({ message: 'Confirm password is required' })
    confirmPassword: string;
}