import { Router } from "express"
import { body } from "express-validator"
import { register, login, refreshAccessToken, logout } from "../controllers/auth.controllers"
import { verifyJWT } from "../middlewares/auth.middlewares"

const router = Router()


// Unsecured Routes
// POST: "/api/v1/auth/register" to create a new user
router.post("/register", [
    body("name", "Enter a valid name").notEmpty(),
    body("username", "Username should be atleast 3 characters").isLength({ min: 3 }),
    body("email", "Enter a valid email").isEmail(),
    body("password", "Password must be atleast 8 characters").isLength({ min: 8 })
], register)

// POST: "/api/v1/auth/login" to login a user
router.post("/login", [
        body("email", "Enter a valid email").isEmail(),
        body("password", "Password must be atleast 8 characters").isLength({ min: 8 })
], login)

// POST: "/api/v1/auth/refresh-token" to refresh access token
router.post("/refresh-token", refreshAccessToken)


// Secured Routes
// POST: "/api/v1/auth/logout" to logout user and clear refresh and access tokens
router.post("/logout", verifyJWT, logout)

export default router