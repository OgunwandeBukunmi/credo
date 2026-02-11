# Overview

Credo is database-agnostic by design.

Instead of locking you into MongoDB, Mongoose, Prisma, or SQL, Credo uses **CRUD adapters** — small objects that define *how* data is stored and retrieved.

You bring your database.  
Credo brings the authentication logic.

---

## Why CRUD Adapters Exist

- No ORM lock-in
- Works with MongoDB, PostgreSQL, MySQL, Redis, or anything else
- Full control over queries and performance
- Easy to test and mock

Credo **never calls your database directly**.  
It only calls the functions you provide.

---

## Adapter Structure

Each adapter is grouped by feature:

```ts
crud: {
  user: UserAdapter,
  refreshToken: RefreshTokenAdapter,
  otp: OTPAdapter
}
```

## Supported Adapters

For Mongodb Database [**MongoDB Adapter**](./mongodbAdapter)

How to create Your own custom Adapter [**Custom Adapter**](./customAdapter)

