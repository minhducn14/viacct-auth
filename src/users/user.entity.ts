import { RefreshToken } from 'src/refresh-token/refresh-token.entity';
import { Entity, Column, PrimaryGeneratedColumn, OneToMany, BeforeInsert, BeforeUpdate } from 'typeorm';
import { Exclude } from 'class-transformer';
import { BadRequestException } from '@nestjs/common';

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

    @BeforeInsert()
    @BeforeUpdate()
    validateAuthenticationMethod() {
        if (this.googleId && this.password) {
            throw new BadRequestException('Fail to save user');
        }

        if (!this.googleId && !this.password) {
            throw new BadRequestException('Fail to save user');
        }
    }
}
