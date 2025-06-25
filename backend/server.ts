import app from "./app"

const port = 5000

app.listen(port, () => {
    console.log(`Chat App Backend Listening on http://localhost:${port}`)
})
