import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { RefreshTokenModule } from 'src/refresh-token/refresh-token.module';
import { MailModule } from 'src/mail/mail.module';

@Module({
  imports: [
    UsersModule,
    JwtModule.register({
      global: true,
      secret: process.env.JWT_ACCESS_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
    JwtModule.registerAsync({
      useFactory: () => ({
        secret: process.env.JWT_REFRESH_SECRET,
        signOptions: { expiresIn: '7d' },
      }),
    }),
    RefreshTokenModule,
    MailModule
  ],
  providers: [AuthService],
  controllers: [AuthController]
})
export class AuthModule { }
