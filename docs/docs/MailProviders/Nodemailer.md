The Nodemailer provider allows Credo to send emails using **SMTP**.

This works with providers like:
- Gmail
- Outlook
- Zoho
- Custom SMTP servers

---

## Installation

```bash
npm install nodemailer
```

## Usage

```js
import { nodemailerMailProvider } from "@oluwabukunmi/credo/mailProviders";
import createAuthSystem from "@oluwabukunmi/credo";

const credo = createAuthSystem({
  ...otherCredoOptions,
  sendMail: nodemailerMailProvider({
    host: "smtp.example.com",
    port: 587,
    secure: false,
    auth: {
      user: "[EMAIL_ADDRESS]",
      pass: "your-password"
    }
  })
});
```