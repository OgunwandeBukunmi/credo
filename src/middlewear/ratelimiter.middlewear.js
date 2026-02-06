import rateLimit from "express-rate-limit";

export const rateLimiter = (minutes, max) => {
    return rateLimit({
        windowMs: minutes * 60 * 1000,
        max: max,
        message: {
            message: "Too many requests, please try again later"
        },
        standardHeaders: true,
        legacyHeaders: false
    })
}