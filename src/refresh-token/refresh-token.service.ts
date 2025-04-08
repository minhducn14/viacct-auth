import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/user.entity';
import { Repository } from 'typeorm';
import { RefreshToken } from './refresh-token.entity';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class RefreshTokenService {
    constructor(
        @InjectRepository(RefreshToken)
        private readonly repo: Repository<RefreshToken>,
    ) { }

    async save(user: User, token: string, device: string, expiresInMs: number) {
        const hashed = await bcrypt.hash(token, 10);
        const expiredAt = new Date(Date.now() + expiresInMs);

        const rt = this.repo.create({ hashedToken: hashed, user, device, expiredAt });
        return this.repo.save(rt);
    }

    async validate(user: User, token: string): Promise<boolean> {
        const list = await this.repo.find({ where: { user } });
        for (const rt of list) {
            const valid = await bcrypt.compare(token, rt.hashedToken);
            if (valid && rt.expiredAt > new Date()) return true;
        }
        return false;
    }

    async revokeAll(user: User) {
        await this.repo.delete({ user });
    }

    async remove(user: User, token: string, device: string) {
        const rt = await this.repo.findOne({ where: { user, device } });
        if (!rt) return false;
        const valid = await bcrypt.compare(token, rt.hashedToken);
        if (!valid) return false;
        await this.repo.delete({ user, device });
        return true;
    }

    async findByUser(user: User) {
        return this.repo.find({ where: { user } });
    }
    async findByDevice(user: User, device: string) {
        return this.repo.findOne({ where: { user, device } });
    }

    async findByToken(user: User, token: string) {
        const rt = await this.repo.findOne({ where: { user } });
        if (!rt) return false;
        const valid = await bcrypt.compare(token, rt.hashedToken);
        if (!valid) return false;
        return rt;
    }
}
