const express = require('express');
const router = express.Router();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const User = require('../models/user');

dotenv.config();

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try{
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

passport.use(new localStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const user  = await User.findOne({$or :[{username: username}, {email: email}]}). select('+password');
        if (!user) {
            return done(null, false, { message: 'Incorrect username or password' });
        }

        const PasswordMatch = await bcrypt.compare(password, user.password);

        if (!PasswordMatch) {
            return done(null, false, { message: 'Incorrect username or password' });
        }
        return done(null, user);

        const userWithoutPassword = user.toObject();
        delete userWithoutPassword.password;
        return done(null, userWithoutPassword);
    } catch (error) {
        return done(error, null);
    }
}
));


