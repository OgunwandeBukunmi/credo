export function createMongoRefreshTokenAdapter(db) {
    const refreshTokens = db.collection("refresh_tokens");

    return {
        async createRefreshToken(data) {
            return refreshTokens.insertOne({
                ...data,
                createdAt: new Date(),
            });
        },

        async findValidRefreshTokenByTokenHash(tokenHash) {
            return refreshTokens.findOne({
                tokenHash,
                revoked: false,
            });
        },

        async revokeRefreshToken(tokenHash) {
            return refreshTokens.updateOne(
                { tokenHash, revoked: false },
                {
                    $set: {
                        revoked: true,
                        revokedAt: new Date(),
                    },
                }
            );
        },
    };
}
