let config = {}

export function initAuthConfig(userconfig) {

    if (!userconfig.jwt) throw new Error("No JWT Keys")
    if (!userconfig.mongo) throw new Error("No Mongodb Credentials")
    if (!userconfig.rateLimit) throw new Error("No Rate Time Limits")
    // if(!userconfig.email) throw new Error("No Email credentials")
    if (!userconfig.sendMail) throw new Error("Didn't provide sendMail function")
    //email part too 

    console.log("Auth System initialized")

    config = userconfig
}

export function getAuthConfig() {
    if (!config) {
        throw new Error("Auth System not initialized")
    }

    return config
}