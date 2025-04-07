import { Controller, Get, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { Request } from 'express';
import { JwtAuthGuard } from 'src/auth/jwt/jwt.guard';
import { User } from './user.entity';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @UseGuards(JwtAuthGuard)
    @Get('/profile')
    getProfile(@Req() req: Request) {
        const user = req.user as User;
        if (!user) {
            throw new UnauthorizedException('User not found');
        }
        return this.usersService.getProfile(user);
    }
}
