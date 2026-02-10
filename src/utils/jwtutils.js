import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"
import crypto from "crypto"
import { getAuthConfig } from "../config/init.js";


const ACCESS_TOKEN_TTL = "15m";



export function signAccessToken(payload) {
    const privateKey = getAuthConfig().jwt.privatekey
    return jwt.sign(payload, privateKey, {
        algorithm: "RS256",
        expiresIn: ACCESS_TOKEN_TTL,
    });
}

// export function signRefreshToken(payload) {
//     return jwt.sign(payload, PRIVATE_KEY, {
//         algorithm: "RS256",
//         expiresIn: REFRESH_TOKEN_TTL,
//     });
// }

export function signRefreshToken() {
    const token = crypto.randomBytes(64).toString("hex");

    const tokenHash = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

    const expiresAt = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
    );

    return { token, tokenHash, expiresAt };
}

export function verifyAccessToken(token) {
    const publicKey = getAuthConfig().jwt.publickey
    return jwt.verify(token, publicKey)
}

export async function verifyRefreshToken(token, tokenHash) {
    try {
        const isValid = await bcrypt.compare(token, tokenHash)
        if (!isValid) return false;
        return true;

    } catch (err) {
        console.error(err)
    }
}



