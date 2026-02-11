
# Custom CRUD Adapter

Credo is database-agnostic. It does not know or care how you store data. Instead, Credo communicates with your database through CRUD adapters—plain JavaScript objects containing asynchronous functions.

Your only responsibility is to implement these functions and return the expected values.

## What is a CRUD Adapter?

A CRUD adapter is an object that groups database logic by domain rather than database type. Credo expects three domains:

- `user`
- `refreshToken`
- `otp`

Each domain exposes a set of async functions that Credo calls internally.

### Adapter Shape

```javascript
const crud = {
  user: {
    findUserByEmail: async (email) => {},
    findUserById: async (id) => {},
    createUser: async (data) => {},
    findUserAndUpdate: async (query, update) => {}
  },
  refreshToken: {
    createRefreshToken: async (data) => {},
    findValidRefreshTokenByTokenHash: async (tokenHash) => {},
    revokeRefreshTokenByTokenHash: async (tokenHash) => {}
  },
  otp: {
    createOTP: async (data) => {},
    findOTPByEmail: async (email , purpose) => {},
    deleteOTPByEmail: async (email , purpose) => {},
    incrementOTPAttempts: async (email , purpose) => {},
    verifyOTP: async (email, purpose) => {}
  }
};
```

## User Adapter

The user adapter handles user persistence.

### Required Functions
```javascript
user: {
  findUserByEmail(email),
  findUserById(id),
  createUser(data),
  findUserAndUpdate(query, update)
}
```

### Function Contracts

- **`findUserByEmail(email)`**: Returns a user object or `null`.
- **`findUserById(id)`**: Returns a user object or `null`.
- **`createUser(data)`**: Creates a user and returns the created user object.
- **`findUserAndUpdate(query, update)`**: Finds a user using `query`, updates it using `update`, and returns the updated user or `null`.

Credo does not enforce how `query` or `update` are structured; you decide how they are interpreted.

## Refresh Token Adapter

Handles refresh token storage and validation.

### Required Functions
```javascript
refreshToken: {
  createRefreshToken(data),
  findValidRefreshTokenByTokenHash(tokenHash),
  revokeRefreshTokenByTokenHash(tokenHash)
}
```

### Function Contracts

- **`createRefreshToken(data)`**: Stores a refresh token and returns the stored token.
- **`findValidRefreshTokenByTokenHash(tokenHash)`**: Returns a valid token object or `null`.
- **`revokeRefreshTokenByTokenHash(tokenHash)`**: Revokes the token and returns `true` or `false`.

## OTP Adapter

Handles one-time password (OTP) operations.

### Required Functions
```javascript
otp: {
  createOTP(data),
  findOTPByEmail(email),
  deleteOTPByEmail(email),
  incrementOTPAttempts(email),
  verifyOTP(email, code)
}
```

### Function Contracts

- **`createOTP(data)`**: Creates an OTP entry and returns the created OTP.
- **`findOTPByEmail(email)`**: Returns OTP data or `null`.
- **`deleteOTPByEmail(email)`**: Deletes OTP records and returns `true` or `false`.
- **`incrementOTPAttempts(email)`**: Increments failed attempts and returns updated OTP data.
- **`verifyOTP(email, code)`**: Verifies the OTP and returns `true` or `false`.

## Example: Simple In-Memory Adapter

This example demonstrates how adapters work without an external database.

```javascript
const users = [];

export const userAdapter = {
  findUserByEmail: async (email) => {
    return users.find(u => u.email === email) || null;
  },

  findUserById: async (id) => {
    return users.find(u => u.id === id) || null;
  },

  createUser: async (data) => {
    const user = { id: Date.now().toString(), ...data };
    users.push(user);
    return user;
  },
  updateUserPassword: async (email, password) => {
    const user = users.find(u => u.email === email);
    if (!user) return null;

    user.password = password;
    return user;
  },
  verfiyUserEmail: async (email) => {
    const user = users.find(u => u.email === email);
    if (!user) return null;

    user.isEmailVerified = true;
    return user;
   }
};

const refreshTokens = []

export const refreshTokenAdapter = {
  createRefreshToken: async (data) => {
    const token = {
      id: Date.now(),
      revoked: false,
      ...data
    }

    refreshTokens.push(token)
    return token
  },

  findValidRefreshTokenByTokenHash: async (tokenHash) => {
    return (
      refreshTokens.find(
        t => t.tokenHash === tokenHash && t.revoked === false
      ) || null
    )
  },

  revokeRefreshTokenByTokenHash: async (tokenHash) => {
    const token = refreshTokens.find(t => t.tokenHash === tokenHash)
    if (!token) return false

    token.revoked = true
    return true
  }
}

const otps = []

export const otpAdapter = {
  createOTP: async (data) => {
    const otp = {
      attempts: 0,
      verified: false,
      createdAt: Date.now(),
      ...data
    }

    otps.push(otp)
    return otp
  },

  findOTPByEmail: async (email , purpose) => {
    return otps.find(o => o.email === email && o.purpose === purpose) || null
  },

  deleteOTPByEmail: async (email , purpose) => {
    const index = otps.findIndex(o => o.email === email && o.purpose === purpose)
    if (index === -1) return false

    otps.splice(index, 1)
    return true
  },

  incrementOTPAttempts: async (email , purpose) => {
    const otp = otps.find(o => o.email === email && o.purpose === purpose)
    if (!otp) return null

    otp.attempts += 1
    return otp
  },

  verifyOTP: async (email, code , purpose) => {
    const otp = otps.find(o => o.email === email && o.purpose === purpose)
    if (!otp) return false

    if (otp.code !== code) {
      otp.attempts += 1
      return false
    }

    otp.verified = true
    return true
  }
}

```

This same pattern applies to any database. Whether using MongoDB, SQL, or Prisma:
- SQL users may map updates manually.
- Prisma users may ignore `query` and map IDs.
- All Credo cares about is the returned value.

### Plugging the Adapter into Credo

```javascript
createAuthSystem({
  crud: {
    user: userAdapter,
    refreshToken: refreshTokenAdapter,
    otp: otpAdapter
  }
});
```

Once provided, Credo will use your adapters internally for all authentication flows.
```