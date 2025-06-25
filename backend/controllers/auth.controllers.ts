import { Request, Response } from "express"
import { validationResult } from "express-validator"
import bcrypt from "bcryptjs"
import User from "../models/user.models"
import { generateAccesAndRefreshToken, UserPayload } from "../utils/AuthHelpers"
import jwt, { UserJwtPayload } from "jsonwebtoken"
import config from "../config/config"
import { RequestWithUserInfo } from "../utils/RequestWithUserInfo"

declare module "jsonwebtoken" {
    export interface UserJwtPayload extends jwt.JwtPayload, UserPayload {}
}

export const register = async (req: Request, res: Response): Promise<any> => {
    let success = false

    // Check if there are errors in request
    const result = validationResult(req)
    if (!result.isEmpty()) {
        // 400 Bad request
        return res.status(400).json({ success, error: result.array() })
    }

    try {
        // Check if user with this username or email already exists
        let user = await User.findOne({
            $or: [
                { username: req.body.username },
                { email: req.body.email }
            ]
        })

        if (user) {
            // 409 Conflict
            if (user.username === req.body.username) return res.status(409).json({ success, error: "An user with this username already exists" })
            if (user.email === req.body.email) return res.status(409).json({ success, error: "An user with this email already exists" })
        }

        // Generating salt and hashing password
        const salt = bcrypt.genSaltSync(10)
        const secPass = bcrypt.hashSync(req.body.password, salt)

        // Creating user
        user = await User.create({
            name: req.body.name,
            username: req.body.username,
            email: req.body.email,
            password: secPass
        })

        const loggedinUser = await User.findById(user._id).select("-password -refreshToken")

        const payload = {
            user: {
                _id: user._id
            }
        }

        // Signing JWT, generating accesstoken and refreshtoken
        const { accessToken, refreshToken } = generateAccesAndRefreshToken(payload)

        // Stateful JWT, Saving refreshtoken to database
        user.refreshToken = refreshToken
        await user.save()

        // Helps in avoiding potential attacks
        const options = {
            httpOnly: true,
            secure: false // true in production
        }

        // Sending acccesstoken and refreshtoken in cookies
        // 201 Created
        return res.status(201).cookie("accesstoken", accessToken, options).cookie("refreshtoken", refreshToken, options).json({ success: true, message: "User account created successfully", user: loggedinUser })
    } catch (err) {
        console.error(err)
        // 500 Internal Server Error
        return res.status(500).send("Internal Server Error")
    }
}

export const login = async (req: Request, res: Response): Promise<any> => {
    let success = false
    
    // Check if there are errors in request
    const result = validationResult(req)
    if(!result.isEmpty()) {
        // 400 Bad request
        return res.status(400).json({ success, error: result.array() })
    }
    try {
        // Check if the user exists in the database
        let user = await User.findOne({ email: req.body.email })

        if (!user) {
            // 404 Not Found
            return res.status(404).json({ success, error: "User does not exist" })
        }

        const checkPassword = bcrypt.compareSync(req.body.password, user.password)
        if (!checkPassword) {
            return res.status(401).json({ success, error: "Invalid user credentials" })
        }

        const loggedinUser = await User.findById(user._id).select("-password -refreshToken")

        const payload = {
            user: {
                _id: user._id
            }
        }

        // Signing JWT, generating accesstoken and refreshtoken
        const { accessToken, refreshToken } = generateAccesAndRefreshToken(payload)

        // Stateful JWT, Saving refreshtoken to database
        user.refreshToken = refreshToken
        await user.save()
        
        // Helps in avoiding potential attacks
        const options = {
            httpOnly: true,
            secure: config.nodeEnv === 'production' // true in production
        }

        // Sending acccesstoken and refreshtoken in cookies
        // 200 Ok
        return res.status(200).cookie("accesstoken", accessToken, options).cookie("refreshtoken", refreshToken, options).json({ success: true, message: "User logged in successfully", user: loggedinUser })
    } catch (err) {
        console.error(err)
        // 500 Internal Server Error
        return res.status(500).send("Internal Server Error")
    }
}

export const refreshAccessToken = async (req: Request, res: Response): Promise<any> => {
    let success = false

    const token = req.cookies.refreshtoken
    if (!token) {
        return res.status(401).json({ success, message: "Unauthorized request" })
    }
    
    try {
        const data = <UserJwtPayload>jwt.verify(token, config.refreshTokenSecret)
        const user = await User.findById(data.user._id).select("refreshToken")
        if (!user) {
            return res.status(401).json({ success, message: "Invalid access token" })
        }

        if (user.refreshToken !== token) {
            return res.status(401).json({ success, message: "Refresh token is expired or used" })
        }

        const payload = {
            user: {
                _id: user._id
            }
        }

        const { accessToken, refreshToken } = generateAccesAndRefreshToken(payload)

        user.refreshToken = refreshToken
        await user.save()

        const options = {
            httpOnly: true,
            secure: config.nodeEnv === 'production'
        }

        return res.status(200).cookie("accesstoken", accessToken, options).cookie("refreshtoken", refreshToken, options).json({ success: true, message: "Access token refreshed" })
    } catch (err) {
        console.error(err)
        return res.status(401).json({ success, message: "Invalid refresh token" })
    }
}

// POST: "/api/v1/auth/logout" to logout user and clear refresh and access tokens
export const logout = async (req: Request, res: Response): Promise<any> => {
    await User.findByIdAndUpdate(
        (req as RequestWithUserInfo).user._id,
        {
            $set: {
                refreshToken: ""
            }
        },
        { new: true }
    )

    const options = {
        httpOnly: true,
        secure: config.nodeEnv === 'production'
    }
    return res.status(200).clearCookie("accesstoken").clearCookie("refreshtoken").json({ success: true, message: "User logged out" })
}