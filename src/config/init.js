let config = {}

export function initAuthConfig(userconfig) {

    if (!userconfig.jwt) throw new Error("No JWT Keys")
    if (!userconfig.rateLimit) throw new Error("No Rate Time Limits")
    if (!userconfig.sendMail) throw new Error("Didn't provide sendMail function")
    if (!userconfig.crud) throw new Error("No CRUD functions")

    //should look like this 
    //           crud: {
    //     user: {
    //       findUserByEmail,
    //       findUserById,
    //       createUser,
    //       updateUserPassword
    //       verfiyUserEmail
    //     },
    //     refreshToken: {
    //       createRefreshToken,
    //       findValidRefreshTokenByTokenHash,,
    //       revokeRefreshToken
    //     },
    //     otp: {
    //       createOTP,
    //       findOTPByEmail,
    //       deleteOTPByEmail,
    //       incrementOTPAttempts,
    //       verifyOTP,
    //     }
    //   }

    console.log("Auth System initialized")

    config = userconfig
}

export function getAuthConfig() {
    if (!config) {
        throw new Error("Auth System not initialized")
    }

    return config
}