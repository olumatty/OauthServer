const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const {v4: uuidv4} = require('uuid');
const {OAuth2Client} = require('google-auth-library');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);


router.post('/register', async (req, res) => { 
    try {
        const { username, password, email } = req.body;

        if (!email || !password ) {
            return res.status(400).json({ message: 'Email and Password fields are required' });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) return res.status(400).json({ message: 'Email already exists' });

        const userId = uuidv4();
        const user = new User({ username, password, email, userId });
        await user.save();

        const token = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 60 * 60 * 1000
        });

        res.status(201).json({ message: 'User registered successfully', userId: user.userId, token });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error: error.message });
    }
});

router.post('/login', async (req, res) => {
    try{
        const {email, password} = req.body;

        if(!username || !password){
            return res.status(400).json({message: 'All fields are required'});
        }

        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({message: 'User email not found'});
        }

        if (user.googleId && !user.password) {
            return res.status(400).json({ message: 'This account uses Google login' });
        }

        const PasswordMatch = await bcrypt.compare(password, user.password);
        if(!PasswordMatch){
            return res.status(401).json({message: 'Incorrect password'});
        }

        const token = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h'});

        const refreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d'});

        res.cookie('token',token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 60*60*1000
        });

        res.cookie('refreshToken', refreshToken, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'none', 
            maxAge: 60*60*1000 
        });

        res.status(200).json({
            message: 'Login successful',
            token, refreshToken,
            userId: user.userId,
            username: user.username,
            email: user.email
        });

    } catch (error) {
        res.status(500).json({message: 'Error logging in', error: error.message});
    }
});

router.post('/logout', (req, res) => {
    try{
        const refreshToken = req.cookies.refreshToken;

        if (refreshToken) {

        console.log (`Attempting to invalidate refreshToken: ${refreshToken}`);
        }
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            path: '/'
        });

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            path: '/'
        });
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ message: 'Error logging out', error: error.message });
    }
});

router.post('/google', async (req, res) => {
    const { idToken } = req.body;

    if (!idToken) {
        return res.status(400).json({ message: 'Google ID token missing' });
    }

    try {
        const ticket = await client.verifyIdToken({
            idToken,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const name = payload.name;
        const email = payload.email;
        const googleId = payload.sub;
        const userId = uuidv4();

        let user = await User.findOne({ $or: [{ googleId: googleId }, { email: email }] });

        if (!user) {
            user = new User({
                googleId,
                email,
                name,
                userId,
            });
            await user.save();
            console.log('New user created:', user);
        } else {
            console.log('User already exists:', user);
        }

        const token = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 60 * 60 * 1000,
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 7 * 24 * 60 * 60 * 1000, // Match refresh token’s 7-day expiration
        });

        res.status(200).json({
            message: 'Google login successful',
            token,
            refreshToken,
            userId: user.userId,
            email: user.email,
            displayName: user.name, // Map 'name' to 'displayName' as expected by frontend
        });
    } catch (error) {
        console.error('Error verifying Google ID token:', error);
        return res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

router.get('/refresh-token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken ||req.body.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const newToken = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

        res.cookie('token', newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 60 * 60 * 1000
        });
        res.status(200).json({ message: 'Token refreshed successfully', token: newToken });
    } catch (error) {
        res.status(500).json({ message: 'Error refreshing token', error: error.message });
        console.error('Error refreshing token:', error);
    }
});


module.exports = router;
