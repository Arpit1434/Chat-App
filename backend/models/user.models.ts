import mongoose from "mongoose"

interface I_UserDocument {
    name: string,
    username: string,
    email: string,
    password: string,
    refreshToken?: string
}

const UserSchema = new mongoose.Schema<I_UserDocument>({
    name: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    refreshToken: {
        type: String
    }
})

const User = mongoose.model<I_UserDocument>('user', UserSchema)
export default User