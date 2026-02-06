# 🚀 Credo Auth

**Credo Auth** is a lightweight, configurable authentication middleware for **Express.js** applications.

It provides a complete, reusable auth system with JWT (access + refresh tokens), email OTP verification, password reset, rate limiting, and MongoDB persistence — without forcing you into a rigid framework.


# Usage
```Javascript
import express from "express";
import { createAuthSystem } from "@your-npm-username/credo";
import mongodb from "mongodb";

// Your custom email sender (can use nodemailer, Resend, etc.)
import { sendMail } from "./sendMail.js";

const app = express();

await mongodb.connect(process.env.MONGODB_URI);

const publicKey  = process.env.JWT_PUBLIC_KEY;  
const privateKey = process.env.JWT_PRIVATE_KEY;

app.use(
  "/api/auth",
  createAuthSystem({
    jwt: {
      publicKey,      
      privateKey,          
    },
    mongo: mongodb,   

    rateLimit: {
      login:        [5, "15 min"],//[minutes , max requests]
      register:     [5, "15 min"],
      logout:       [10, "15 min"],
      refreshToken: [10, "15 min"],
      forgotPassword: [3, "10 min"],
      resetPassword:  [5, "10 min"],
    },

    email: {
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      from: process.env.EMAIL_FROM || "no-reply@yourapp.com",
      resendApiKey: process.env.RESEND_API_KEY,
      mode: process.env.NODE_ENV === "production" ? "production" : "development",
    },
        sendMail,
  })
);

app.listen(3000, () => console.log("Server running on port 3000"));

```
        
