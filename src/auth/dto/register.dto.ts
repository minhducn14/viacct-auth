export class RegisterDto {
    company: string;
    firstName: string;
    lastName: string;
    username: string;
    email: string;
    phone?: string;
    password: string;
    confirmPassword: string;
}