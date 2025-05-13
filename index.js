const express = require('express')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const session = require('express-session')
const passport = require('passport')
const bcrypt = require('bcrypt')
const cors = require('cors')
const app = express();
const PORT = 8000;

dotenv.config()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}))

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60000 }
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('MongoDB connected')
}).catch(err => {
    console.error('MongoDB connection error:', err)
}



app.listen(PORT, ()=>{
    console.log(`The server is running on port ${PORT}`)
});

 