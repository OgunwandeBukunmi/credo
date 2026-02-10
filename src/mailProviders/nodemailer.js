//code for email setups

import nodemailer from "nodemailer"

function createNodemailerMailProvider(config) {
    const transporter = nodemailer.createTransport(config);

    const sendMail = async ({ to, subject, text, html }) => {

        await transporter.sendMail({
            from: config.from,
            to,
            subject,
            text,
            html,
        });
    }
    return sendMail


}