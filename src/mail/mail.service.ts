import { Injectable } from '@nestjs/common';
import nodemailer from 'nodemailer';

@Injectable()
export class MailService {
    private transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.GOOGLE_USERNAME, pass: process.env.GOOGLE_APP_PASSWORD },

    });

    async sendVerificationEmail(to: string, subject: string, html: string) {
        return await this.transporter.sendMail({
            from: '"viAct Auth" <no-reply@viact.com>',
            to,
            subject,
            html,
        });
    }
}
