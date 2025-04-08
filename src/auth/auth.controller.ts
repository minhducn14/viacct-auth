import {
    BadRequestException,
    Body,
    ConflictException,
    Controller,
    Get,
    Headers,
    NotFoundException,
    Post,
    Query,
    Req,
    UnauthorizedException,
    UseGuards
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { RefreshTokenService } from 'src/refresh-token/refresh-token.service';
import { User } from 'src/users/user.entity';
import { Logger } from '@nestjs/common';
import { MailService } from 'src/mail/mail.service';
import { LoginDto } from './dto/login.dto';
import { instanceToPlain } from 'class-transformer';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt/jwt.guard';
import { Request } from 'express';

const ACCESS_TOKEN_EXP = '15m';
const REFRESH_TOKEN_EXP = '7d';
const EMAIL_TOKEN_EXP = '10m';


@Controller('auth')
export class AuthController {

    private readonly logger = new Logger(AuthController.name);
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly refreshTokenService: RefreshTokenService,
        private readonly mailService: MailService,
        private readonly authService: AuthService,
    ) {

    }

    @Post('register')
    async register(@Body() dto: RegisterDto, @Headers('user-agent') userAgent: string,) {
        const response = await this.authService.register(dto, userAgent);
        return response;
    }


    @Post('login')
    async login(@Body() dto: LoginDto, @Headers('user-agent') userAgent: string) {
        const response = await this.authService.login(dto, userAgent);
        return response;

    }

    @Post('google-login')
    async googleLogin(@Body('idToken') idToken: string, @Headers('user-agent') userAgent: string) {
        const response = await this.authService.googleLogin(idToken, userAgent);
        return response;

    }


    @Post('verify-email')
    async verifyEmail(@Body() body: { token: string }, @Headers('user-agent') userAgent: string) {
        const response = await this.authService.verifyEmail(body.token, userAgent);
        return response;
    }



    @UseGuards(JwtAuthGuard)
    @Post('refresh-token')
    async refreshToken(@Req() req: Request, @Headers('user-agent') userAgent: string) {
        const user = req.user as User;
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            throw new UnauthorizedException('Authorization header is missing');
        }
        const response = await this.authService.refreshToken(user, authHeader, userAgent);
        return response;
    }


}
