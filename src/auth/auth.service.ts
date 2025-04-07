import { BadRequestException, ConflictException, Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
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
        private readonly mailService: MailService
    ) {
        this.googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    }

    async register(dto: RegisterDto, userAgent: string) {
        try {
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
                timeRevoke: new Date(0),
            });
            if (!user) {
                throw new BadRequestException('Failed to create user');
            }

            //Gửi email xác minh
            const response = await this.sendVerificationEmail(user);
            return response;
        } catch (err) {
            this.logger.error('Error registering user', err);
            throw new BadRequestException('Failed to register user');
        }
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
            return {
                message: 'Your registration was successful. A verification email has been sent to your inbox. Please check your spam folder if you do not see it within a few minutes.'
            };
        } catch (err) {
            this.logger.error('Error sending verification email', err);
            throw new BadRequestException('Failed to send verification email');
        }
    }

    async verifyEmail(token: string, userAgent: string) {
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

    async login(dto: LoginDto, userAgent: string) {
        const { username, password } = dto;

        //Validate user credentials
        const user = await this.validateCredentials(username, password);

        //Tạo access token và refresh token
        const tokens = await this.generateTokens(user.id, user.email, userAgent);
        const safeUser = instanceToPlain(user) as User;
        return { safeUser, ...tokens };
    }

    async googleLogin(idToken: string, userAgent: string) {
        // Verify the token with Google
        const ticket = await this.googleClient.verifyIdToken({
            idToken: idToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();

        if (!payload) {
            throw new Error('Invalid token payload');
        }

        const { email, family_name, given_name } = payload;
        //Check xem user có tồn tại không
        if (!email) {
            throw new NotFoundException('Email not found in token payload');
        }

        let user = await this.usersService.findByEmail(email);

        //Nếu user không tồn tại thì tạo mới
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
        }
        //Nếu user đã tồn tại 
        else {
            //Kiểm tra xem user có tồn tại với password authentication không
            if (!user.googleId) {
                throw new UnauthorizedException('Account already registered');
            }

            //Kiểm tra user đã đăng nhập bằng tài khoản google khác
            if (user.googleId !== payload.sub) {
                throw new UnauthorizedException('Invalid Google account');
            }

            //Check xem user có bị khóa không
            if (user.timeRevoke > new Date()) {
                throw new UnauthorizedException('User is revoked');
            }
        }

        //Tạo token
        const tokens = await this.generateTokens(user.id, email, userAgent);
        const safeUser = instanceToPlain(user) as User;
        return { safeUser, ...tokens };

    }

    async generateTokens(userId: number, email: string, device: string) {
        //Validate user
        await this.validateUser(email);

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


    private async validateCredentials(username: string, password: string): Promise<User> {
        const user = await this.usersService.findByUsername(username);
        if (!user) throw new NotFoundException('User not found');
        if (!user.password) throw new UnauthorizedException('Unauthorized');
        if (user.timeRevoke > new Date()) throw new UnauthorizedException('User is revoked');
        if (!user.isEmailVerified) throw new UnauthorizedException('User is not verified');
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new UnauthorizedException('Invalid credentials');
        return user;
    }

    async validateUser(email: string) {
        const userCheck = await this.usersService.findByEmail(email);
        if (!userCheck) {
            throw new NotFoundException('User not found');
        }
        if (userCheck.timeRevoke > new Date()) {
            throw new UnauthorizedException('User is revoked');
        }
        if (!userCheck.isEmailVerified) {
            throw new UnauthorizedException('User is not verified');
        }
    }

}
