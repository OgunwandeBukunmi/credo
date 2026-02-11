import { signAccessToken } from "../utils/jwtutils.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { signRefreshToken } from "../utils/jwtutils.js";
import { ObjectId } from "mongodb";
import { getAuthConfig } from "../config/init.js";
import { generateOTP, hashOTP } from "../utils/otp.js";


export const loginController = async (req, res) => {
    const { email, password } = req.body


    //How login works.
    //First we find the user by email.
    //Then we compare the password.
    //If the password is correct, we generate a token.
    //Then we send the token to the client.
    //The client will store the token in the browser.
    //The client will send the token in the header of every request.
    //The server will verify the token.
    //If the token is valid, the server will send the data.
    //If the token is not valid, the server will send an error.

    const { findUserByEmail } = getAuthConfig().crud.user
    const { createRefreshToken } = getAuthConfig().crud.refreshToken


    const user = await findUserByEmail(email)

    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }


    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid password" });
    }

    const accessToken = signAccessToken({ email, userId: user._id, role: user.role })
    const refreshToken = signRefreshToken()

    const data = { ...refreshToken, userId: user._id, revoked: false }
    await createRefreshToken(data)

    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 15 * 60 * 60 * 1000,
    }

    res.cookie("refreshToken", refreshToken.token, cookieOptions);

    //redirect to home page 
    res.json({ accessToken, user });
}

export const registerController = async (req, res) => {

    //Get the email and password from the request body.
    //Check if the user already exists.
    //If the user exists, return an error.
    //If the user does not exist, hash the password.
    //Insert the user into the database.
    //Generate an access token
    //Generate an refresh token and send it as a cookie
    //store the refresh token in the db
    //Send the token to the client.
    try {

        //functions are findUserByEmail and createUser createRefreshToken
        const { findUserByEmail, createUser } = getAuthConfig().crud.user
        const { createRefreshToken } = getAuthConfig().crud.refreshToken

        const { email, password } = req?.body || {};


        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }
        const user = await findUserByEmail(email)

        if (user) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const userData = { email, password: hashedPassword, role: ["user"], isEmailVerified: false }
        const newUser = await createUser(userData)



        const accessToken = signAccessToken({ email, userId: newUser._id, role: ["user"] })

        const refreshToken = signRefreshToken()
        const data = { ...refreshToken, userId: newUser.insertedId, revoked: false }
        await createRefreshToken(data)

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 60 * 60 * 1000,
        }

        res.cookie("refreshToken", refreshToken.token, cookieOptions);

        //redirect to home page 
        res.json({ accessToken, message: "User Registers Verify Email", user: newUser });
    } catch (error) {
        console.log(error)
    }

}


export async function requestEmailVerificationController(req, res) {

    const purpose = "email_verification"
    const { findUserByEmail } = getAuthConfig().crud.user
    const { createOTP, deleteOTPByEmail } = getAuthConfig().crud.otp
    const sendMail = getAuthConfig().sendMail
    try {
        const { email } = req?.body || {};

        if (!email) {
            return res.status(400).json({
                message: "Email is required"
            });
        }


        const user = await findUserByEmail(email);

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        if (user.isEmailVerified) {
            return res.status(400).json({
                message: "Email already verified"
            });
        }

        await deleteOTPByEmail(email, purpose);

        const genOtp = generateOTP();
        const hashedOTP = hashOTP(genOtp);
        const otp = await createOTP({
            email,
            purpose: "email_verification",
            otp: hashedOTP
        });

        // 3. Send email
        await sendMail({
            to: email,
            subject: "Verify your email",
            text: `Your verification code is ${genOtp}`,
            otp: genOtp,
            html: `<p>Your verification code is <strong>${genOtp}</strong></p>`
        });

        return res.status(200).json({
            message: "Verification email sent"
        });

    } catch (error) {
        console.error("Request verify email error:", error);
        return res.status(500).json({
            message: "Internal server error"
        });
    }
}


export async function verifyEmailController(req, res) {
    const purpose = "email_verification"
    const { findUserByEmail, verfiyUserEmail } = getAuthConfig().crud.user
    const { findOTPByEmail, incrementOTPAttempts, deleteOTPByEmail } = getAuthConfig().crud.otp
    try {
        const { email, otp } = req?.body || {};

        if (!email || !otp) {
            return res.status(400).json({
                message: "Email and OTP are required"
            });
        }


        const user = await findUserByEmail(email)
        if (!user) {

            return res.status(404).json({
                message: "User not found"
            });
        }
        // 1. Verify OTP
        if (user.isEmailVerified) {
            return res.status(400).json({
                message: "Email already verified"
            });
        }

        const otpRecord = await findOTPByEmail(email, purpose);

        if (!otpRecord) {
            return res.status(400).json({
                message: "OTP not found"
            });
        }

        if (otpRecord.attempts >= 5) {
            await deleteOTPByEmail(email, purpose);
            return res.status(400).json({
                message: "Too many attempts. Please request a new OTP"
            });
        }

        const hashedUserOTP = hashOTP(otp)

        if (hashedUserOTP !== otpRecord.otp) {
            await incrementOTPAttempts(email, purpose);

            return res.status(400).json({
                message: "Invalid or expired OTP"
            });
        }

        // 2. Mark user as verified
        await verfiyUserEmail(email);

        // 3. Cleanup OTP
        await deleteOTPByEmail(email, purpose);

        return res.status(200).json({
            message: "Email verified successfully"
        });

    } catch (error) {
        console.error("Verify email error:", error);
        return res.status(500).json({
            message: "Internal server error"
        });
    }
}


export const logoutController = async (req, res) => {
    try {

        const { revokeRefreshToken } = getAuthConfig().crud.refreshToken

        const refreshTokenClient = req.cookies.refreshToken;

        // Already logged out
        if (!refreshTokenClient) {
            return res.status(204).json({ message: "No Refresh Token found (Already Logged out)" });
        }

        const tokenHash = crypto
            .createHash("sha256")
            .update(refreshTokenClient)
            .digest("hex");

        const revokedAt = new Date()
        await revokeRefreshToken(
            tokenHash, revokedAt
        );//THOUGHT

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
        });

        return res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
};

export const refreshTokenController = async (req, res) => {

    try {
        const { findUserById, } = getAuthConfig().crud.user
        const { createRefreshToken, findValidRefreshTokenByTokenHash, revokeRefreshToken } = getAuthConfig().crud.refreshToken
        const refreshTokenClient = req.cookies.refreshToken;

        if (!refreshTokenClient) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const tokenHash = crypto
            .createHash("sha256")
            .update(refreshTokenClient)
            .digest("hex")

        console.log(tokenHash)
        const token = await findValidRefreshTokenByTokenHash(tokenHash);

        if (!token) {
            return res.status(401).json({ message: "Unauthorized", token });
        }
        const id = new ObjectId(token.userId)
        const user = await findUserById(id)

        console.log(token)

        await revokeRefreshToken(tokenHash); //THOUGHT
        const accessToken = signAccessToken({ email: user.email, role: user.role })
        const refreshToken = signRefreshToken()

        const data = { ...refreshToken, userId: user._id, revoked: false }
        await createRefreshToken(data)

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 60 * 60 * 1000,
        }

        res.cookie("refreshToken", refreshToken.token, cookieOptions);

        //redirect to home page 
        res.json({ accessToken });
    } catch (err) {
        console.error(err)
    }



}

export const resetPasswordRequestController = async (req, res) => {


    const purpose = "reset_password"
    const { email } = req.body;
    const { findUserByEmail, } = getAuthConfig().crud.user
    const { deleteOTPByEmail, createOTP } = getAuthConfig().crud.otp
    const sendMail = getAuthConfig().sendMail

    const user = await findUserByEmail(email);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }
    const genOTP = generateOTP();
    const otp = hashOTP(genOTP);
    await deleteOTPByEmail(email, purpose)

    const data = {
        email,
        otp,
        purpose,
        userId: user["_id"],
        expiresAt: new Date(Date.now + 10 * 60 * 1000),
        verified: false,
        attempts: 0,
        createdAt: new Date()

    }
    await createOTP(data)

    sendMail({
        to: email,
        subject: "Reset Password",
        text: `Your OTP is ${otp}`,
        otp: genOTP,
    });
    res.json({ message: "User Gotten and OTP has been sent" })
}
export const resetPasswordVerifyController = async (req, res) => {

    //get otp from body
    //findOTPByEmail
    //verifyOTP
    //incrementOTPAttempts
    //findOneAndUpdateOTPs
    const purpose = "reset_password"
    const { email, otp } = req.body
    const { findOTPByEmail, verifyOTP } = getAuthConfig().crud.otp
    const record = await findOTPByEmail(email, purpose)


    if (!record) {
        return res.status(400).json({ message: "Invalid OTP" })
    }

    if (record.expiresAt > new Date()) {
        return res.status(400).json({ message: 'OTP expired' })
    }

    if (record.attempts >= 5) {
        return res.status(424).json({ message: "Too many attempts" })
    }

    const hashedUserOTP = hashOTP(otp)
    if (hashedUserOTP !== record.otp) {
        await incrementOTPAttempts(email, purpose)
        res.status(400).json({ message: "Incorrect OTP" })
    }

    await verifyOTP(email, purpose)
    //check if otp matches the otp from the db
    //if yes process 200 ok if not 404
    res.status(200).json({ message: "OTP has been verified" })
}
export const resetPasswordConfirmController = async (req, res) => {

    const { email, newpassword } = req.body
    try {
        //findUserByEmail
        //findOTPByEmail
        //updateUserByEmail
        const { findUserByEmail, updateUserPassword } = getAuthConfig().crud.user
        const { findOTPByEmail } = getAuthConfig().crud.otp
        const record = await findOTPByEmail(email)

        const user = await findUserByEmail(email)

        if (!record || !record.verified) {
            res.status(400).json({ message: "Unauthorized" })
        }

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }


        const hashedPassword = await bcrypt.hash(newpassword, 10)

        const newUser = await updateUserPassword(email, hashedPassword)
        //THOUGHT
        res.json({ message: "Password Reset" })

    } catch (err) {
        console.error(err)
    }
}