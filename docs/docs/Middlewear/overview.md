
# Overview

This document provides an overview of the middleware used in this project, specifically focusing on common implementations for authentication.


## Custom Ratelimiter

This middlewear is used to limit the number of requests a user can make to a route in a given time frame.
```js
import {rateLimiter} from "@oluwabukunmi/credo/middlewear"
import express from "express"
const {login , register , refreshToken , logOut , resetPassword} = getAuthConfig().rateLimit


rateLimiter(10, 15) //rateLimiter(minutes, trys)
const router = express.Router()

router.post("/route", rateLimiter(10, 15), (req,res)=>{
    res.send("Hello World")
})

```

## Authenticate User

This middlewear checks if the user is authorized to access the route i.e if the user has a valid access token
```js
import {authenticateJWT} from "@oluwabukunmi/credo/middlewear"
import express from "express"
const router = express.Router()

router.post("/route", authenticateJWT, (req,res)=>{
    res.send("Hello World")
})

```

## Role Based Access Control

This middlewear checks if the user has a valid role to access the route

```js
import {requireRole} from "@oluwabukunmi/credo/middlewear"
import express from "express"
const router = express.Router()

router.post("/route", requireRole("admin"), (req,res)=>{
    res.send("Hello World")
})

```

## Request Logger

This middlewear logs the request to the console for easier debugging 😁
```js
import {requestLogger} from "@oluwabukunmi/credo/middlewear"
import express from "express"
const router = express.Router()

router.post("/route", requestLogger, (req,res)=>{
    res.send("Hello World")
})

```
