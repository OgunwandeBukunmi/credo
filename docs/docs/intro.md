---
id: intro
title: Introduction
---
# Quick Start

# 🚀 Credo Auth

**Credo Auth** is a lightweight, configurable authentication middleware for **Express.js** applications.

It provides a complete, reusable auth system with JWT (access + refresh tokens), email OTP verification, password reset, rate limiting, and MongoDB persistence — without forcing you into a rigid framework.

#### Note: CREDO makes use of cookies so make sure that in your requests and CORS settings they aren't blocked


# Usage
```Javascript
import express from "express";
import { createAuthSystem } from "@your-npm-username/credo";
import mongodb from "mongodb";
import createAuthSystem from "@oluwabukunmi/credo";
import clientPromise from "./src/config/mongodbconfig.js";
import { createMongoAuthAdapter } from "@oluwabukunmi/credo/adapters";
import { createResendMailProvider } from "@oluwabukunmi/credo/mailProviders"

const app = express();

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

const client = await clientPromise
const db = client.db("example")

const privateKey = JWT_PRIVATEKEY

const publicKey = JWT_PUBLICKEY


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
        


# Routes


## Available Endpoints

### Authentication
- `POST /login`
- `POST /register`
- `POST /logout`
- `POST /refresh-token`

### Password & OTP
- `POST /forgot-password`
- `POST /reset-password`
- `POST /verify-otp`

**POST `api/auth/login`**

#### Request Body
```json
{
  "email": "string",
  "password": "string"
}

```

#### Response Body

```json

{
  "accessToken": "string",
  "refreshToken": "string",(will be automatically sent as an http-only cookie)
  "userId": "number"
}

```

**POST `api/auth/signup`**

#### Request Body

```json 

{
  "email": "string",
  "password": "string"
}

```

#### Response Body 

```json
{
  "accessToken": "string",
  "refreshToken": "string",(will be automatically sent as an http-only cookie)
  "userId": "number"
}
```

**POST `api/auth/logout`**

#### Request Body

NONE


#### Response Body 

```json
{
   message: "Logged out successfully"
 }

```

**POST `api/auth/refresh-token`**

#### Request Body

NONE

#### Response Body

```json
{
  
  "accessToken": "string"

}
```

**POST `api/auth/reset-password/request`**

#### Request Body

```json
{
  "email" : "string"
}
```

#### Response Body

```json
{ 
  message: "User Gotten and OTP has been sent" 
}
```

**POST `api/auth/reset-password/verify`**

### Request Body

```json
{
  "email" : "string",
  "otp" : "number"
}
```

#### Response Body

```json
{ 
  message: "OTP has been verified" 
}

```
**POST `api/auth/reset-password/confirm`**

#### Request Body

```json
{
   "email" : "string",
   "newpassword" :"string"
}
```

#### Response Body

```json
{
   message: "Password Reset" 
}
```

Go to  [Authentication Overview](./authentication/overview.md) for more insight.















