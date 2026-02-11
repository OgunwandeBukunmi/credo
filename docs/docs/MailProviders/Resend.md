# Resend Mail Provider

The Resend provider integrates Credo with the **Resend Email API**.

Resend is recommended for **production applications** due to its reliability and developer experience.

---

## Installation

```bash
npm install resend
```

## Usage

```js
import { resendMailProvider } from "@oluwabukunmi/credo/mailProviders";
import createAuthSystem from "@oluwabukunmi/credo";

const credo = createAuthSystem({
  ...otherCredoOptions,
  sendMail: resendMailProvider({
    apiKey: "re_123456789",
    from: "[EMAIL_ADDRESS]"
  })
});
```