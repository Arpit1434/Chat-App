import dotenv from "dotenv"

dotenv.config()

interface Config {
    nodeEnv: string,
    accessTokenSecret: string,
    accessTokenExpiresIn: string,
    refreshTokenSecret: string,
    refreshTokenExpiresIn: string
}

const config: Config = {
    nodeEnv: process.env.NODE_ENV || 'development',
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET || '',
    accessTokenExpiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '1d',
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || '',
    refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '10d'
}

export default config