# 🚀 Credo Auth

**Credo Auth** is a lightweight, configurable authentication middleware for **Express.js** applications.

It provides a complete, reusable auth system with JWT (access + refresh tokens), email OTP verification, password reset, rate limiting, and MongoDB persistence — without forcing you into a rigid framework.


# Usage
```Javascript
import express from "express";
import { createAuthSystem } from "@your-npm-username/credo";
import mongodb from "mongodb";
import createAuthSystem from "@oluwabukunmi/credo";
import fs from "fs"
import path from "path"
import clientPromise from "./src/config/mongodbconfig.js";
import { createMongoAuthAdapter } from "@oluwabukunmi/credo/adapters";
import { createResendMailProvider } from "@oluwabukunmi/credo/mailProviders"

const app = express();

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

const client = await clientPromise
const db = client.db("example")

const privateKey = fs.readFileSync(
    path.join(process.cwd(), "keys/private.key"),
    "utf8"
);

const publicKey = fs.readFileSync(
    path.join(process.cwd(), "keys/public.key"),
    "utf8"
);


app.use(
  "/api/auth",
  createAuthSystem({
    jwt: {
      publicKey,      
      privateKey,          
    },
     crud: createMongoAuthAdapter(db), 

    rateLimit: {
      login:        [5, "15 min"],//[minutes , max requests]
      register:     [5, "15 min"],
      logout:       [10, "15 min"],
      refreshToken: [10, "15 min"],
      forgotPassword: [3, "10 min"],
      resetPassword:  [5, "10 min"],
    },
      sendMail: createResendMailProvider(process.env.RESEND_API_KEY, process.env.EMAIL_FROM),
      mode: process.env.NODE_ENV === "production" ? "production" : "development",
    })
);

app.listen(3000, () => console.log("Server running on port 3000"));

```
        
