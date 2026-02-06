import authRoutes from "./routes/auth.route.js"
import cookieParser from "cookie-parser"
import { initAuthConfig } from "./config/init.js"

const createAuthSystem = (config) => {
    initAuthConfig(config)

    const router = authRoutes()

    return [
        cookieParser(),
        router
    ]
}

export default createAuthSystem


//create mail function for resend and nodemailer and also console log the email if the mode is development or if the user decides
//correct the readme setup code
//mongodb vs mongoose issue (solution make use of functions in the config)
