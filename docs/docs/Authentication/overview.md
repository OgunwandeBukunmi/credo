---
id: overview
title: Overview
---
#  Overview

This section documents the authentication system provided by **Credo**.

The authentication module is responsible for:
- User registration
- User login
- Token refresh
- Logout  
- Password reset using OTP

All authentication logic is exposed through HTTP endpoints and is **framework-agnostic**, meaning you can use it with any frontend (web, mobile, server-side, etc.).

## How Authentication Works

Credo uses a **token-based authentication** strategy:

- **Access Tokens**
  - Short-lived
  - Returned in the response body
  - Used to authenticate protected API requests

- **Refresh Tokens**
  - Long-lived
  - Stored securely as **HTTP-only cookies**
  - Used to generate new access tokens without re-login

This approach balances **security** and **developer experience**.

👉 **[Authentication Routes](./routes)** 
