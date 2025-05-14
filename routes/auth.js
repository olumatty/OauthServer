const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const passport = require('passport');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const generateToken = require('../middleware/generateToken');

router.post('/register',async (req, res)=> {
    try{
        const {username, password, email} = req.body;
        const existingUser = await User.findOne({$or :[{username: username}, {email: email}]});
        if (existingUser) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username: username,
            password: hashedPassword,
            email: email,
        });
        await newUser.save();
        // Generate JWT token
        const token = generateToken(newUser);
        res.status(201).json({ message: 'User created successfully' });
        
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
})

router.post('/login', passport.authenticate('local', {session:false}),(err, user, info) => {
    if (err) {
        return res.status(500).json({ message: 'Internal server error' });
    }
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    // Generate JWT token
    const token = generateToken(user);
    res.json({ message: 'Login successful', token:token });
    res.status(200).json({ message: 'Login successful', token });
});


router.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.status(200).json({ message: 'Logout successful' });
    });
});

module.exports = router;
