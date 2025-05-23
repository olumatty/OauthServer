const express = require('express')
const dotenv = require('dotenv')
const mongoose = require('mongoose')

const cors = require('cors')
const cookieParser = require('cookie-parser')
const authRoutes = require('./routes/auth')

const app = express()
dotenv.config()

const PORT = 8000;

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'userId', 'token'],
}))

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.use('/api/v1/auth', authRoutes)


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
}
)           


