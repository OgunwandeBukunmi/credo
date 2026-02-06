import { signAccessToken } from "../utils/jwtutils.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { createRefreshToken } from "../utils/jwtutils.js";
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

    const db = getAuthConfig().mongo
    const User = db.collection("users");
    const RefreshToken = db.collection("refresh_tokens")

    const user = await User.findOne({ email })

    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }


    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid password" });
    }

    const accessToken = signAccessToken({ email, userId: user._id, role: user.role })
    const refreshtoken = crypto.randomBytes(64).toString("hex");

    const refreshToken = await createRefreshToken()
    await RefreshToken.insertOne({ ...refreshToken, userId: user._id, revoked: false })

    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 15 * 60 * 60 * 1000,
    }

    res.cookie("refreshToken", refreshToken.token, cookieOptions);

    //redirect to home page 
    res.json({ accessToken });
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
        const db = getAuthConfig().mongo
        const User = db.collection("users");
        const RefreshToken = db.collection("refresh_tokens")

        const { email, password } = req?.body || {};


        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }
        const user = await User.findOne({ email })

        if (user) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const newUser = await User.insertOne({ email, password: hashedPassword, role: ["user"] })



        const accessToken = signAccessToken({ email, userId: newUser._id, role: ["user"] })

        const refreshToken = await createRefreshToken()
        await RefreshToken.insertOne({ ...refreshToken, userId: newUser.insertedId, revoked: false })

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 60 * 60 * 1000,
        }

        res.cookie("refreshToken", refreshToken.token, cookieOptions);

        //redirect to home page 
        res.json({ accessToken });
    } catch (error) {
        console.log(error)
    }

}

export const logoutController = async (req, res) => {
    try {
        const db = getAuthConfig().mongo
        const RefreshToken = db.collection("refresh_tokens")
        const refreshTokenClient = req.cookies.refreshToken;

        // Already logged out
        if (!refreshTokenClient) {
            return res.status(204).json({ message: "No Refresh Token found (Already Logged out)" });
        }

        const tokenHash = crypto
            .createHash("sha256")
            .update(refreshTokenClient)
            .digest("hex");

        await RefreshToken.findOneAndUpdate(
            { tokenHash, revoked: false },
            {
                $set: {
                    revoked: true,
                    revokedAt: new Date(),
                },
            }
        );

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
    //Get Refresh token from the cookie
    //verify the refresh token
    //
    //Generate a new access token.
    //Send the access token to the client.
    try {
        const db = getAuthConfig().mongo
        const User = db.collection("users");
        const RefreshToken = db.collection("refresh_tokens")
        const refreshTokenClient = req.cookies.refreshToken;

        if (!refreshTokenClient) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const tokenHash = crypto
            .createHash("sha256")
            .update(refreshTokenClient)
            .digest("hex")

        console.log(tokenHash)
        const token = await RefreshToken.findOne({ tokenHash, revoked: false });

        if (!token) {
            return res.status(401).json({ message: "Unauthorized", token });
        }

        const user = await User.findOne({ _id: new ObjectId(token.userId) })

        console.log(token)

        await RefreshToken.findOneAndUpdate({ tokenHash: tokenHash }, { $set: { revoked: true } });
        const accessToken = signAccessToken({ email: user.email, role: user.role })
        const refreshToken = createRefreshToken()
        await RefreshToken.insertOne({ ...refreshToken, userId: user._id, revoked: false })

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
    //Properly code the send email function
    //which collection does the otp actually get sent to 

    const { email } = req.body;
    const db = getAuthConfig().mongo
    const sendMail = getAuthConfig().sendMail
    const User = db.collection("users");
    const PasswordResetOTPs = db.collection("otps");
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }
    const otp = generateOTP();
    const hashedOTP = hashOTP(otp);
    await PasswordResetOTPs.deleteMany({ email })

    await PasswordResetOTPs.insertOne({
        email,
        hashedOTP,
        userId: user["_id"],
        expiresAt: new Date(Date.now + 10 * 60 * 1000),
        verified: false,
        attempts: 0,
        createdAt: new Date()

    })

    sendMail({
        to: email,
        subject: "Reset Password",
        text: `Your OTP is ${otp}`,
    });
    res.json({ message: "User Gotten and OTP has been sent" })
}
export const resetPasswordVerifyController = async (req, res) => {

    //get otp from body
    const { email, otp } = req.body
    const db = getAuthConfig().mongo
    const PasswordResetOTPs = db.collection("otps");
    const record = await PasswordResetOTPs.findOne({ email })



    if (!record) {
        return res.status(400).json({ message: "Invalid OTP" })
    }

    if (record.expiresAt > new Date()) {
        return res.status(400).json({ message: 'OTP expired' })
    }

    if (record.attempts >= 5) {
        return res.status(424).json({ message: "Too many attempts" })
    }

    const recordOTP = hashOTP(otp)
    if (recordOTP !== record.hashedOTP) {
        await PasswordResetOTPs.findOneAndUpdate({ email }, { $inc: { attempts: 1 } })
        res.status(400).json({ message: "Incorrect OTP" })
    }

    await PasswordResetOTPs.findOneAndUpdate({ email }, { $set: { verified: true } })
    //check if otp matches the otp from the db
    //if yes process 200 ok if not 404
    res.status(200).json({ message: "OTP has been verified" })
}
export const resetPasswordConfirmController = async (req, res) => {

    const { email, newpassword } = req.body


    const db = getAuthConfig().mongo
    const User = db.collection("users");
    const PasswordResetOTPs = db.collection("otps")
    const record = await PasswordResetOTPs.findOne({ email })

    const user = await User.findOne({ email })

    if (!record || !record.verified) {
        res.status(400).json({ message: "Unauthorized" })
    }

    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }


    const hashedPassword = await bcrypt.hash(newpassword, 10)

    const newUser = await User.findOneAndUpdate({
        email
    }, {
        $set: {
            password: hashedPassword
        }
    })
    //take the email and password
    //update the password associated to the email

    res.json({ message: "Password Reset" })
}