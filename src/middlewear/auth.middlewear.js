import { verifyAccessToken } from "../utils/jwtutils.js";


export const authenticateJWT = async (req, res, next) => {

    //something to do handle and give errros for jwt expiration
    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" })
    }
    try {
        const decoded = verifyAccessToken(token)

        if (!decoded) {
            return res.status(401).json({ message: "Unauthorized" })
        }

        req.user = decoded;
        next();
    } catch (err) {
        // Handle different JWT errors
        if (err.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Access token expired" });
        } else if (err.name === "JsonWebTokenError") {
            return res.status(401).json({ message: "Invalid token" });
        } else {
            return res.status(500).json({ message: "Something went wrong with token verification" });
        }
    }
}

export const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user.role.includes(role)) {
            return res.status(401).json({ message: "Unauthorized admin only" })
        }
        next();
    }
}