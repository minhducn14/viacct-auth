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
    UnauthorizedException
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { RefreshTokenService } from 'src/refresh-token/refresh-token.service';
import { User } from 'src/users/user.entity';
import { Logger } from '@nestjs/common';
import { MailService } from 'src/mail/mail.service';

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
    ) {

    }

    @Post('register')
    async register(@Body() dto: RegisterDto, @Headers('user-agent') userAgent: string,) {
        const { email, username, password, confirmPassword, ...rest } = dto;

        //Check email và username đã tồn tại chưa
        const emailTaken = await this.usersService.findByEmail(email);
        const usernameTaken = await this.usersService.findByUsername(username);
        if (emailTaken || usernameTaken) {
            throw new ConflictException('Email or username already used');
        }

        //Check password và confirmPassword có giống nhau không
        if (password !== confirmPassword) {
            throw new BadRequestException('Passwords do not match');
        }

        //Hash password
        const hashed = await bcrypt.hash(password, 10);
        const user = await this.usersService.create({
            ...rest,
            email,
            username,
            password: hashed,
            isEmailVerified: false,
            timeRevoke: new Date(),
        });
        if (!user) {
            throw new BadRequestException('Failed to create user');
        }

        //Gửi email xác minh
        return this.sendVerificationEmail(user).then(() => {
            return { message: 'Verification email sent' };
        }).catch((err) => {
            this.logger.error('Error sending verification email', err);
            throw new BadRequestException('Failed to send verification email');
        });
    }

    async generateTokens(userId: number, email: string, device: string) {
        //Check xem user có tồn tại không
        const userCheck = await this.usersService.findByEmail(email);
        if (!userCheck) {
            throw new NotFoundException('User not found');
        }
        //Check xem user có bị khóa không
        if (userCheck.timeRevoke > new Date()) {
            throw new UnauthorizedException('User is revoked');
        }
        //Check xem user có xác minh email không
        if (!userCheck.isEmailVerified) {
            throw new UnauthorizedException('User is not verified');
        }

        //Tạo access token và refresh token
        const payload = { userId, email };
        const accessToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_ACCESS_SECRET,
            expiresIn: ACCESS_TOKEN_EXP,
        });
        const refreshToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_REFRESH_SECRET,
            expiresIn: REFRESH_TOKEN_EXP,
        });

        //Lưu refresh token vào database
        const user = await this.usersService.findByEmail(email);
        const ms = 7 * 24 * 60 * 60 * 1000;
        if (!user) {
            throw new BadRequestException('User not found');
        }
        await this.refreshTokenService.save(user, refreshToken, device, ms);
        return { accessToken, refreshToken };

    }

    private async sendVerificationEmail(user: User) {
        try {
            //Check xem user có tồn tại không
            const userCheck = await this.usersService.findByEmail(user.email);
            if (!userCheck) {
                throw new NotFoundException('User not found');
            }
            //Check xem user có bị khóa không
            if (userCheck.timeRevoke > new Date()) {
                throw new UnauthorizedException('User is revoked');
            }
            //Check xem user có xác minh email không
            if (userCheck.isEmailVerified) {
                throw new UnauthorizedException('User is already verified');
            }

            // Tao token xác minh email
            const token = this.jwtService.sign(
                { sub: user.id, email: user.email },
                { secret: process.env.JWT_EMAIL_SECRET, expiresIn: EMAIL_TOKEN_EXP },
            );
            //Tạo link xác minh email
            const verifyUrl = `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;

            //Gửi email xác minh

            await this.mailService.sendVerificationEmail(user.email, 'Email Verification',
                `<p>Dear ${user.username},</p>
                <p>Your administrator has just requested that you update your ViAct account by performing the following action(s): Verify Email.</p>
                <p>Click on the link below to start this process.</p>
                <p><a href="${verifyUrl}">Verify Email</a></p>
                <p>This link will expire within 10 min.</p>
                <p>If you are unaware that your administrator has requested this, just ignore this message and nothing will be changed.</p>
                <p>Best regards,</p>
                <p>viAct Team</p>`);
        } catch (err) {
            this.logger.error('Error sending verification email', err);
            throw new BadRequestException('Failed to send verification email');
        }
    }

    @Get('verify-email')
    async verifyEmail(@Query('token') token: string, @Headers('user-agent') userAgent: string) {
        try {
            //Giải mã token bằng secret email
            const payload = this.jwtService.verify(token, {
                secret: process.env.JWT_EMAIL_SECRET,
            });

            //Kiểm tra user tồn tại
            const user = await this.usersService.findByEmail(payload.email);
            if (!user) throw new NotFoundException('User not found');

            //Nếu đã xác minh rồi thì không cần xác minh lại
            if (user.isEmailVerified) {
                return { message: 'Email already verified' };
            }

            //Cập nhật trạng thái xác minh
            user.isEmailVerified = true;
            await this.usersService.update(user);

            return { message: 'Email verified successfully' };
        } catch (err) {
            this.logger.error('Error verifying email', err);
            throw new BadRequestException('Invalid or expired token');
        }
    }


}
