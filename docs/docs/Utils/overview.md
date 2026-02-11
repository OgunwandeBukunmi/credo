# Overview

This document provides an overview of the utils used in this project, specifically focusing on common implementations for authentication.


## JWT Utils

This utils is used to generate and verify JWT tokens.
```js
import {signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken} from "@oluwabukunmi/credo/utils"

const accessToken = signAccessToken(user)
const refreshToken = signRefreshToken(user)

const {user} = verifyAccessToken(accessToken)
const {user} = verifyRefreshToken(refreshToken)

```

## OTP Utils

This utils is used to generate and verify OTPs.
```js
import {generateOTP, hashOTP} from "@oluwabukunmi/credo/utils"


const otp = generateOTP()
const hashedOTP = hashOTP(otp)



```

## Password Utils

This utils is used to hash and verify passwords.
```js
import {hashPassword, verifyPassword} from "@oluwabukunmi/credo/utils"

const hashedPassword = hashPassword(password)
const isMatch = verifyPassword(password, hashedPassword)

```
