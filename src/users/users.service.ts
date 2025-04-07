import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';

@Injectable()
export class UsersService {
    constructor(@InjectRepository(User) private repo: Repository<User>) { }

    findByEmail(email: string): Promise<User | null> {
        return this.repo.findOne({ where: { email } });
    }

    findByUsername(username: string): Promise<User | null> {
        return this.repo.findOne({ where: { username } });
    }

    findById(id: number): Promise<User | null> {
        return this.repo.findOne({ where: { id } });
    }

    findByGoogleId(googleId: string): Promise<User | null> {
        return this.repo.findOne({ where: { googleId } });
    }

    findAll(): Promise<User[]> {
        return this.repo.find();
    }

    create(user: User): Promise<User> {
        return this.repo.save(user);
    }

    update(user: User): Promise<User> {
        return this.repo.save(user);
    }

    delete(id: number): Promise<void> {
        return this.repo.delete(id).then(() => { });
    }
}

