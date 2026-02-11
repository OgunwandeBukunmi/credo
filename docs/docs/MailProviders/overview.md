# Mail Providers Overview

Mail providers define how emails are sent inside CREDO.
The system is provider-based, meaning you can swap email services
without changing your authentication logic.

Each mail provider implements the same interface, ensuring
a consistent API regardless of the underlying service.

## Available Providers

- **Console Provider**  
  Logs emails to the console (useful for development and testing).

- **Nodemailer Provider**  
  Sends emails using SMTP-based services like Gmail or Outlook.

- **Resend Provider**  
  Uses the Resend API for modern transactional email delivery.

- **Custom Mail Provider**  
  Allows you to plug in any email service of your choice.

## Provider Responsibilities

Every mail provider must:
- Send verification emails
- Send OTP or password reset emails
- Accept standardized input data from CREDO

## Learn More

- [Console Provider](./console)
- [Nodemailer Provider](./nodemailer)
- [Resend Provider](./resend)
- [Create a Custom Mail Provider](./customMailProvider)
