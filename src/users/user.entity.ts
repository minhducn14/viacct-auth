import { RefreshToken } from 'src/refresh-token/refresh-token.entity';
import { Entity, Column, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
import { Exclude } from 'class-transformer';

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    company: string;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column({ unique: true })
    username: string;

    @Exclude()
    @Column({ unique: true })
    email: string;

    @Exclude()
    @Column({ nullable: true })
    phone: string;

    @Exclude()
    @Column({ nullable: true })
    password: string;

    @Exclude()
    @Column({ nullable: true })
    googleId: string;

    @Exclude()
    @Column({ nullable: true })
    timeRevoke: Date;

    @Exclude()
    @Column({ default: false })
    isEmailVerified: boolean;

    @Exclude()
    @OneToMany(() => RefreshToken, token => token.user)
    refreshTokens: RefreshToken[];
}
