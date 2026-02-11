import express from "express";
import {
    loginController,
    registerController, refreshTokenController,
    logoutController, resetPasswordRequestController,
    resetPasswordVerifyController,
    resetPasswordConfirmController,
    requestEmailVerificationController,
    verifyEmailController
} from "../controllers/auth.contoller.js";
import { rateLimiter } from "../middlewear/ratelimiter.middlewear.js";
import { getAuthConfig } from "../config/init.js";

const router = express.Router();

function authRoutes() {

    const { login, register, refreshToken, logOut, resetPassword } = getAuthConfig().rateLimit
    console.log(`Login is for ${login[0]} minutes and ${login[1]} trys`)
    router.post("/login", rateLimiter(login[0] || 5, login[1] || 15), loginController);
    router.post("/register", rateLimiter(register[0] || 5, register[1] || 15), registerController);
    router.post("/verify-email/request", rateLimiter(5, 5), requestEmailVerificationController);
    router.post("/verify-email/verify", rateLimiter(5, 5), verifyEmailController);
    router.post("/refresh-token", rateLimiter(refreshToken[0] || 5, refreshToken[1] || 20), refreshTokenController);
    router.post("/logout", rateLimiter(logOut[0] || 5, logOut[1] || 20), logoutController);
    router.post("/reset-password/request", rateLimiter(resetPassword[0] || 5, resetPassword[1] || 5), resetPasswordRequestController)
    router.post("/reset-password/verify", rateLimiter(5, 5), resetPasswordVerifyController)
    router.post("/reset-password/confirm", rateLimiter(5, 5), resetPasswordConfirmController)

    return router

}




export default authRoutes;
