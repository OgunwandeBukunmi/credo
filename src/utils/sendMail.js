import { Resend } from "resend";
import { getAuthConfig } from "../config/init.js";

let client = null;
let initialized = false;
let isTestMode = false;
let fromAddress = null;

function initMailer() {
    if (initialized) return;

    const config = getAuthConfig();

    if (!config.email) {
        throw new Error("Email config not provided");
    }

    const {
        resendApiKey ,
        from,
        mode
    } = config.email;

    isTestMode = mode === "test";
    fromAddress = from;

    if (!isTestMode) {
        client = new Resend(resendApiKey);
    }

    initialized = true;
}

export async function sendMail({ to, subject, html, text }) {

    try{
         initMailer();
    // 🧪 TEST MODE
    if (isTestMode) {
        console.log("📧 EMAIL (TEST MODE)");
        console.log({ from: fromAddress, to, subject, text, html });
        console.log("━━━━━━━━━━━━━━━━━━━━━━");
        return;
    }

    // 🚀 PRODUCTION MODE
    await client.emails.send({
        from: fromAddress,
        to,
        subject,
        html,
        text
    });
    }
    catch(err){
        console.error(err.message)
    }
    
}
