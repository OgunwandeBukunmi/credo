
# Mongodb Adapter

This example shows how to implement Credo’s CRUD adapters using the **native MongoDB driver** (not Mongoose).

## Prerequisites

- MongoDB client instance
- Connected database

```Javascript
import { createMongoAuthAdapter } from "@oluwabukunmi/credo/adapters";
import createAuthSystem from "@oluwabukunmi/credo";
import clientPromise from "./src/config/mongodbconfig.js";

const client = await clientPromise
const db = client.db("example")

app.use("/api/v1/auth", createAuthSystem({
    ...
    crud: createMongoAuthAdapter(db),
    ...
}))
```


## BEHIND THE SCENE OF THE ADAPTER

```js
export function createMongoOTPAdapter(db) {
    const otps = db.collection("otp");

    return {
        async createOTP(data) {
            return otps.insertOne({
                ...data,
                createdAt: new Date(),
            });
        },

        async findOTPByEmail(email, purpose) {
            return otps.findOne({ email, purpose });
        },

        async deleteOTPByEmail(email, purpose) {
            return otps.deleteMany({ email, purpose });
        },

        async incrementOTPAttempts(email, purpose) {
            return otps.updateOne(
                { email, purpose },
                { $inc: { attempts: 1 } }
            );
        },

        async verifyOTP(email, purpose) {
            return otps.updateOne(
                { email, purpose },
                {
                    $set: {
                        verified: true,
                        verifiedAt: new Date(),
                    },
                }
            );
        },
    };
}


export function createMongoRefreshTokenAdapter(db) {
    const refreshTokens = db.collection("refresh_tokens");

    return {
        async createRefreshToken(data) {
            return refreshTokens.insertOne({
                ...data,
                createdAt: new Date(),
            });
        },

        async findValidRefreshTokenByTokenHash(tokenHash) {
            return refreshTokens.findOne({
                tokenHash,
                revoked: false,
            });
        },

        async revokeRefreshToken(tokenHash) {
            return refreshTokens.updateOne(
                { tokenHash, revoked: false },
                {
                    $set: {
                        revoked: true,
                        revokedAt: new Date(),
                    },
                }
            );
        },
    };
}


import { ObjectId } from "mongodb";

export function createMongoUserAdapter(db) {
    const users = db.collection("users");

    return {
        async findUserByEmail(email) {
            return users.findOne({ email });
        },

        async findUserById(id) {
            return users.findOne({ _id: new ObjectId(id) });
        },

        async createUser(data) {
            return users.insertOne({
                ...data,
                createdAt: new Date(),
                updatedAt: new Date(),
            });
        },

        async updateUserPassword(email, hashedPassword) {
            return users.updateOne(
                { email },
                {
                    $set: {
                        password: hashedPassword,
                        updatedAt: new Date(),
                    },
                }
            );
        },

        async verfiyUserEmail(email) {
            return users.updateOne(
                { email },
                {
                    $set: {
                        isEmailVerified: true,
                        updatedAt: new Date(),
                    },
                }
            );
        },
    };
}

```