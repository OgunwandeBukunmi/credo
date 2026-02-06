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


//add the max-minutes rate for each of the auth routes in the config
//add the email credentials
//add the new code like config editing, more controllers , more files for sending email and otp , and routes, and editing the code to incorporate the new component rate limiting
