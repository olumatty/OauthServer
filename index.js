const express = require('express')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const session = require('express-session')
const passport = require('passport')
const cors = require('cors')
const app = express();
const PORT = 8000;
const authRoutes = require('./routes/auth')
const generateToken = require('./middleware/generateToken')

dotenv.config()
require('./config/googleAuth')


app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
}))

app.use(session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60000 }
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('MongoDB connected')
}).catch(err => {
    console.error('MongoDB connection error:', err)
});

app.use('/api/auth', authRoutes)

app.get('/api/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/login',
    session: false
}), (req, res) => {
    // Successful authentication, redirect home.
    const token = generateToken(req.user);
    res.redirect(`http://localhost:5173/auth-success?token=${token}`);
}
);
app.get('/api/auth/github', passport.authenticate('github', {
}));

app.get('/auth/github/callback', passport.authenticate('github', {
    failureRedirect: '/login',

    session: false
}), (req, res) => {
    // Successful authentication, redirect home.
    const token = generateToken(req.user);
    res.redirect(`http://localhost:5173/auth-success?token=${token}`);
}
);

app.get('/api/status', (res, req) => {
    res.json({status: 'Api is running'})
} )

app.listen(PORT, () => {
    console.log(`The server is running on port ${PORT}`)
});

 