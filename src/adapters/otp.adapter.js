export function createMongoOTPAdapter(db) {
    const otps = db.collection("otps");

    return {
        async createOTPs(data) {
            return otps.insertOne({
                ...data,
                createdAt: new Date(),
            });
        },

        async findOTPByEmail(email) {
            return otps.findOne({ email });
        },

        async deleteOTPs(email) {
            return otps.deleteMany({ email });
        },

        async incrementOTPAttempts(email) {
            return otps.updateOne(
                { email },
                { $inc: { attempts: 1 } }
            );
        },

        async verifyOTP(email) {
            return otps.updateOne(
                { email },
                {
                    $set: {
                        verified: true,
                        verifiedAt: new Date(),
                    },
                }
            );
        },
    };
}
