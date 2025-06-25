import jwt, { UserJwtPayload } from "jsonwebtoken"
import { Request, Response, NextFunction } from "express"
import config from "../config/config"
import User from "../models/user.models"
import { UserPayload } from "../utils/AuthHelpers"
import { RequestWithUserInfo } from "../utils/RequestWithUserInfo"

declare module "jsonwebtoken" {
    export interface UserJwtPayload extends jwt.JwtPayload, UserPayload {}
}

export const verifyJWT = async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    let success = false

    const token = req.cookies.accesstoken
    if (!token) {
        return res.status(401).json({ success, message: "Unauthorized request" })
    }
    
    try {
        const data = <UserJwtPayload>jwt.verify(token, config.accessTokenSecret)
        const user = await User.findById(data.user._id).select("-password -refreshToken")
        if (!user) {
            return res.status(401).json({ success, message: "Invalid access token" })
        }
        
        (req as RequestWithUserInfo).user = user
        next()
    } catch (err) {
        console.error(err)
        return res.status(401).json({ success, message: "Invalid access token" })
    }
}
