import { Router, Request, Response } from "express"
import { verifyJWT } from "../middlewares/auth.middlewares"
import { RequestWithUserInfo } from "../utils/RequestWithUserInfo"

const router = Router()

router.get("/", verifyJWT, async (req: Request, res: Response): Promise<any> => {
    try {
        return res.status(200).json({ user: (req as RequestWithUserInfo).user })
    } catch (err) {
        console.error(err)
        return res.status(500).send("Internal Server Error")
    }
})

export default router