import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn } from 'typeorm';
import { User } from '../users/user.entity';

@Entity()
export class RefreshToken {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    hashedToken: string;

    @Column()
    device: string;

    @Column()
    expiredAt: Date;

    @CreateDateColumn()
    createdAt: Date;

    @ManyToOne(() => User, user => user.refreshTokens, { onDelete: 'CASCADE' })
    user: User;
}
