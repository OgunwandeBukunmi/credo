
# Mongodb Adapter

This example shows how to implement Credo’s CRUD adapters using the **native MongoDB driver** (not Mongoose).

## Prerequisites

- MongoDB client instance
- Connected database

```Javascript
import { createMongoAuthAdapter } from "@oluwabukunmi/credo/adapters";
import createAuthSystem from "@oluwabukunmi/credo";
import clientPromise from "./src/config/mongodbconfig.js";

const client = await clientPromise
const db = client.db("example")

app.use("/api/v1/auth", createAuthSystem({
    ...
    crud: createMongoAuthAdapter(db),
    ...
}))
```