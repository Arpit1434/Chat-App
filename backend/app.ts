import express from "express"
import connectToMongo from "./db"
import cors from "cors"
import cookieParser from "cookie-parser"
import AuthRouter from "./routes/auth.routes"
import DemoRouter from "./routes/demo.routes"

connectToMongo()
const app = express()

app.use(cors())
app.use(express.json())
app.use(cookieParser())

app.use("/api/v1/auth", AuthRouter)
app.use("/api/v1/demo", DemoRouter)

export default app