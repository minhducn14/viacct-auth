import {
    BadRequestException,
    ConflictException,
    Injectable,
    Logger,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { MailService } from 'src/mail/mail.service';
import { RefreshTokenService } from 'src/refresh-token/refresh-token.service';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from 'src/users/user.entity';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { instanceToPlain } from 'class-transformer';

const ACCESS_TOKEN_EXP = '15m';
const REFRESH_TOKEN_EXP = '7d';
const EMAIL_TOKEN_EXP = '10m';

@Injectable()
export class AuthService {
    private readonly googleClient: OAuth2Client;
    private readonly logger = new Logger(AuthService.name);

    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly refreshTokenService: RefreshTokenService,
        private readonly mailService: MailService,
    ) {
        this.googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    }

    async register(dto: RegisterDto, userAgent: string) {
        try {
            const { email, username, password, confirmPassword, ...rest } = dto;

            // Kiểm tra email và username đã được sử dụng hay chưa
            const emailTaken = await this.usersService.findByEmail(email);
            const usernameTaken = await this.usersService.findByUsername(username);
            if (emailTaken || usernameTaken) {
                throw new ConflictException('Email or username already used');
            }

            // Kiểm tra mật khẩu và xác nhận mật khẩu có khớp nhau không
            if (password !== confirmPassword) {
                throw new BadRequestException('Passwords do not match');
            }

            // Hash password
            const hashed = await bcrypt.hash(password, 10);
            const user = await this.usersService.create({
                ...rest,
                email,
                username,
                password: hashed,
                isEmailVerified: false,
                timeRevoke: new Date(0),
            });

            // Nếu không tạo được user thì ném lỗi
            if (!user) {
                throw new BadRequestException('Failed to create user');
            }

            // Gửi email xác minh
            return await this.sendVerificationEmail(user);
        } catch (err) {
            this.logger.error('Error registering user', err);
            throw new BadRequestException('Failed to register user');
        }
    }

    private async sendVerificationEmail(user: User) {
        try {
            const currentTime = new Date();
            // Kiểm tra xem user có tồn tại hay không
            const userCheck = await this.usersService.findByEmail(user.email);
            if (!userCheck) {
                throw new NotFoundException('User not found');
            }
            // Kiểm tra xem user có bị khóa không
            if (userCheck.timeRevoke > currentTime) {
                throw new UnauthorizedException('User is revoked');
            }
            // Kiểm tra xem user đã xác minh email chưa
            if (userCheck.isEmailVerified) {
                throw new UnauthorizedException('User is already verified');
            }

            // Tạo token xác minh email
            const token = this.jwtService.sign(
                { sub: user.id, email: user.email },
                { secret: process.env.JWT_EMAIL_SECRET, expiresIn: EMAIL_TOKEN_EXP },
            );
            // Tạo link xác minh email
            const verifyUrl = `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;

            // Gửi email xác minh
            await this.mailService.sendVerificationEmail(
                user.email,
                'Email Verification',
                `<p>Dear ${user.username},</p>
         <p>Your administrator has just requested that you update your ViAct account by performing the following action(s): Verify Email.</p>
         <p>Click on the link below to start this process.</p>
         <p><a href="${verifyUrl}">Verify Email</a></p>
         <p>This link will expire within 10 min.</p>
         <p>If you are unaware that your administrator has requested this, just ignore this message and nothing will be changed.</p>
         <p>Best regards,</p>
         <p>viAct Team</p>`
            );

            return {
                message:
                    'Your registration was successful. A verification email has been sent to your inbox. Please check your spam folder if you do not see it within a few minutes.',
            };
        } catch (err) {
            this.logger.error('Error sending verification email', err);
            throw new BadRequestException('Failed to send verification email');
        }
    }

    async verifyEmail(token: string, userAgent: string) {
        try {
            // Giải mã token bằng secret email
            const payload = this.jwtService.verify(token, {
                secret: process.env.JWT_EMAIL_SECRET,
            });

            // Kiểm tra user tồn tại
            const user = await this.usersService.findByEmail(payload.email);
            if (!user) throw new NotFoundException('User not found');

            // Nếu đã xác minh rồi thì không cần xác minh lại
            if (user.isEmailVerified) {
                return { message: 'Email already verified' };
            }

            // Cập nhật trạng thái xác minh
            user.isEmailVerified = true;
            await this.usersService.update(user);

            return { message: 'Email verified successfully' };
        } catch (err) {
            this.logger.error('Error verifying email', err);
            throw new BadRequestException('Invalid or expired token');
        }
    }

    async login(dto: LoginDto, userAgent: string) {
        const { username, password } = dto;

        // Kiểm tra thông tin đăng nhập
        const user = await this.validateCredentials(username, password);

        // Tạo access token và refresh token
        const tokens = await this.generateTokens(user, userAgent);
        const safeUser = instanceToPlain(user) as User;
        return { safeUser, ...tokens };
    }

    async googleLogin(idToken: string, userAgent: string) {
        // Verify token với Google
        const ticket = await this.googleClient.verifyIdToken({
            idToken: idToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();

        if (!payload) {
            throw new Error('Invalid token payload');
        }

        // Lấy thông tin từ payload
        const { email, family_name, given_name } = payload;
        if (!email) {
            throw new NotFoundException('Email not found in token payload');
        }

        let user = await this.usersService.findByEmail(email);

        // Nếu user không tồn tại thì tạo mới
        if (!user) {
            user = await this.usersService.create({
                email,
                username: email,
                firstName: given_name || 'Google',
                lastName: family_name || 'User',
                isEmailVerified: true,
                company: `${family_name || 'Personal'} project's`,
                timeRevoke: new Date(0),
                googleId: payload.sub,
            });

            if (!user) {
                throw new BadRequestException('Failed to create user');
            }
        } else {
            // Nếu user đã tồn tại
            if (!user.googleId) {
                throw new UnauthorizedException('Account already registered');
            }

            if (user.googleId !== payload.sub) {
                throw new UnauthorizedException('Invalid Google account');
            }

            const currentTime = new Date();
            if (user.timeRevoke > currentTime) {
                throw new UnauthorizedException('User is revoked');
            }
        }

        const tokens = await this.generateTokens(user, userAgent);
        const safeUser = instanceToPlain(user) as User;
        return { safeUser, ...tokens };
    }

    async generateTokens(user: User, device: string) {
        // Xác thực user (đã được validate thông qua các bước trước)
        await this.validateUser(user);

        // Tạo access token và refresh token
        const payload = { userId: user.id, email: user.email };
        const accessToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_ACCESS_SECRET,
            expiresIn: ACCESS_TOKEN_EXP,
        });
        const refreshToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_REFRESH_SECRET,
            expiresIn: REFRESH_TOKEN_EXP,
        });

        // Thời gian hết hạn của refresh token: 7 ngày (tính theo milisecond)
        const ms = 7 * 24 * 60 * 60 * 1000;
        await this.refreshTokenService.save(user, refreshToken, device, ms);
        return { accessToken, refreshToken };
    }

    private async validateCredentials(username: string, password: string): Promise<User> {
        const user = await this.usersService.findByUsername(username);
        if (!user) throw new NotFoundException('User not found');
        if (!user.password) throw new UnauthorizedException('Unauthorized');

        const currentTime = new Date();
        if (user.timeRevoke > currentTime) throw new UnauthorizedException('User is revoked');
        if (!user.isEmailVerified) throw new UnauthorizedException('User is not verified');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new UnauthorizedException('Invalid credentials');

        return user;
    }

    async validateUser(user: User) {
        const currentTime = new Date();
        if (!user) {
            throw new NotFoundException('User not found');
        }
        if (user.timeRevoke > currentTime) {
            throw new UnauthorizedException('User is revoked');
        }
        if (!user.isEmailVerified) {
            throw new UnauthorizedException('User is not verified');
        }
    }
}
