export function createMongoOTPAdapter(db) {
    const otps = db.collection("otp");

    return {
        async createOTP(data) {
            return otps.insertOne({
                ...data,
                createdAt: new Date(),
            });
        },

        async findOTPByEmail(email, purpose) {
            return otps.findOne({ email, purpose });
        },

        async deleteOTPByEmail(email, purpose) {
            return otps.deleteMany({ email, purpose });
        },

        async incrementOTPAttempts(email, purpose) {
            return otps.updateOne(
                { email, purpose },
                { $inc: { attempts: 1 } }
            );
        },

        async verifyOTP(email, purpose) {
            return otps.updateOne(
                { email, purpose },
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
