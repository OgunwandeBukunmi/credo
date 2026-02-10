

export function consoleMailProvider() {


    function sendMail({ to, subject, otp }) {

        console.log("📧 EMAIL (TEST MODE)");
        console.log("To:", to);
        console.log("Subject:", subject);
        console.log("OTP:", otp);
        console.log("━━━━━━━━━━━━━━━━━━━━━━");

    }
    return sendMail

}
