import { createMongoUserAdapter } from "./user.adapter.js";
import { createMongoRefreshTokenAdapter } from "./refreshToken.adapter.js";
import { createMongoOTPAdapter } from "./otp.adapter.js";

export function createMongoAuthAdapter(db) {
    return {
        user: createMongoUserAdapter(db),
        refreshToken: createMongoRefreshTokenAdapter(db),
        otp: createMongoOTPAdapter(db),
    };
}
