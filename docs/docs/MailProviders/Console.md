# Console Mail Provider

The Console Mail Provider is intended for **development and testing**.

Instead of sending real emails, it logs the email content directly to the console.

---

## When to Use

- Local development
- Testing authentication flows
- Debugging OTP and reset emails

---

## Example Usage

```js
import { consoleMailProvider } from "@oluwabukunmi/credo/mailProviders";
import createAuthSystem from "@oluwabukunmi/credo";

const credo = createAuthSystem({
  ...otherCredoOptions,
  sendMail: consoleMailProvider()
});

```

## Console Output

When an email is "sent", you'll see output like this in your terminal:

```
📧 Email Sent
To: user@example.com
Subject: Your OTP Code
Body: Your OTP is 123456

```