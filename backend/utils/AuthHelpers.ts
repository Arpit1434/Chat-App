import { Types } from "mongoose"
import jwt from "jsonwebtoken"
import config from "../config/config"

export interface UserPayload {
    user: {
        _id: Types.ObjectId
    }
}

export const generateAccesAndRefreshToken = (data: UserPayload) => {
    const accessToken = jwt.sign(data, config.accessTokenSecret, { expiresIn: 30 })
    const refreshToken = jwt.sign(data, config.refreshTokenSecret, { expiresIn: 120 })
    return { accessToken, refreshToken }
}