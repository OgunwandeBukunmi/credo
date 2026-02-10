//code for resend
import { Resend } from "resend";

export function createResendMailProvider(APIKEY, from) {


    const sendMail = async ({ to, subject, text, html }) => {
        const resend = new Resend(APIKEY);
        await resend.emails.send({
            from,
            to,
            subject,
            text,
            html,
        });
    }


    return sendMail
}

