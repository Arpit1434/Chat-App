import { Request } from "express"
import { Types } from "mongoose"

export interface RequestWithUserInfo extends Request {
    user: {
        _id: Types.ObjectId,
        name: string,
        username: string,
        email: string
    }
}