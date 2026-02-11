# Routes

This shows how the frontend/client would communicate with the authentication system

## POST `/login`

Authenticate a user and receive an access token.

### Example

```js
const response = await fetch("http://backend-url/api/v1/auth/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  credentials: "include", // IMPORTANT: allows http-only cookies
  body: JSON.stringify({
    email: "user@email.com",
    password: "user-password"
  })
});

const data = await response.json();

// Access token returned in response body
const accessToken = data.accessToken;

// Store access token (example: memory or localStorage)
localStorage.setItem("accessToken", accessToken);

//Refresh Token is received as an http-only cookie

```

## POST `/signup`

Create a new user account.

### Example

```js
const response = await fetch("http://backend-url/api/v1/auth/signup", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  credentials: "include",
  body: JSON.stringify({
    email: "user@email.com",
    password: "user-password"
  })
});

const data = await response.json();

localStorage.setItem("accessToken", data.accessToken);

//Refresh Token is sent as an http-only cookie
```

## POST `/verify-email/request`

Request for an OTP message 

```js
const response = await fetch("http://backend-url/api/v1/auth/verify-email/request", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    email: "user@email.com"
  })
});

const data = await response.json()

const result = data.message // {message : "Verification OTP Email sent"}

```

## POST `/verify-email/verify`

Verify the OTP sent to the user.

```js
const response  = await fetch("http://backend-url/api/v1/auth/verify-email/verify", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    email: "user@email.com",
    otp: "123456"
  })
});


const data = await response.json()

const result  = data.message // { message: "Email Verified" }
```

## POST `/logout`
Logs the user out and revokes the refresh token.
```js
await fetch("http://backend-url/api/v1/auth/logout", {
  method: "POST",
  credentials: "include"
});

// Clear stored access token
localStorage.removeItem("accessToken");
```

## POST `/refresh-token`

Generate a new access token using the refresh token cookie.

```js
const response = await fetch("http://backend-url/api/v1/auth/refresh", {
  method: "POST",
  credentials: "include"
});

const data = await response.json();

// Replace expired access token
localStorage.setItem("accessToken", data.accessToken);
```

## POST `/reset-password/request`

Request for an OTP message 

```js
const response = await fetch("http://backend-url/api/v1/auth/reset-password/request", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    email: "user@email.com"
  })
});

const data = await response.json()

const result = data.message // {message : "User Gotten and OTP has been sent}


```

## POST `/reset-password/verify`

Verify the OTP sent to the user.

```js
const response  = await fetch("http://backend-url/api/v1/auth/password/verify-otp", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    email: "user@email.com",
    otp: "123456"
  })
});


const data = await response.json()

const result  = data.message // { message: "OTP has been verified" }
```

## POST `/reset-password/confirm`

Set a new password after OTP verification.

```js
await fetch("http://backend-url/api/v1/auth/password/reset/confirm", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    email: "user@email.com",
    newPassword: "new-secure-password"
  })
});

```


