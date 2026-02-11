import { ObjectId } from "mongodb";

export function createMongoUserAdapter(db) {
    const users = db.collection("users");

    return {
        async findUserByEmail(email) {
            return users.findOne({ email });
        },

        async findUserById(id) {
            return users.findOne({ _id: new ObjectId(id) });
        },

        async createUser(data) {
            return users.insertOne({
                ...data,
                createdAt: new Date(),
                updatedAt: new Date(),
            });
        },

        async updateUserPassword(email, hashedPassword) {
            return users.updateOne(
                { email },
                {
                    $set: {
                        password: hashedPassword,
                        updatedAt: new Date(),
                    },
                }
            );
        },

        async verfiyUserEmail(email) {
            return users.updateOne(
                { email },
                {
                    $set: {
                        isEmailVerified: true,
                        updatedAt: new Date(),
                    },
                }
            );
        },
    };
}
