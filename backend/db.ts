import mongoose from "mongoose"

const mongoURI = 'mongodb://localhost:27017/?authMechanism=DEFAULT'

const connectToMongo = () => {
    mongoose.connect(mongoURI, { dbName: 'chatapp' })
    .then(() => {
        console.log("Connected to Mongo Successfully")
    })
    .catch((err) => {
        console.log(err)
    })
}

export default connectToMongo