# Creating a Custom Mail Provider

To create your own provider, you only need to return sendMail.

## Minimal Template

```js
export function createCustomMailProvider(config) {
    //setup config for that provider
    
  const sendMail = async ({ to, subject, text, html }) => {
        //send mail using your provider
  };

  return sendMail;
}