const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const User = require('../models/user');
const bcrypt = require('bcrypt');
const localStrategy = require('passport-local').Strategy;
const GithubStrategy = require('passport-github2').Strategy;

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
        const user  = await User.findOne({email: email}). select('+password');
        if (!user) {
            return done(null, false, { message: 'Incorrect email or password' });
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

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const existingUser = await User.findOne({ googleId: profile.id });
        if (existingUser) {
            return done(null, existingUser);
        }
        const newUser = new User({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value || profile.email,
            profilePicture: profile.photos[0].value || profile.picture,
        });
        await newUser.save();
        done(null, newUser);
    } catch (error) {
        done(error, null);
    }
}));

passport.use(new GithubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope:['read:user', 'user:email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const existingUser = await User.findOne({ githubId: profile.id });
        if (existingUser) {
            return done(null, existingUser);
        }
        const newUser = new User({
            githubId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value || profile.email,
            profilePicture: profile.photos[0].value || profile.picture,
        });
        await newUser.save();
        done(null, newUser);
    } catch (error) {
        done(error, null);
    }
}));

/*passport.use(new AppleStrategy({
    clientID: process.env.APPLE_CLIENT_ID,
    teamID: process.env.APPLE_TEAM_ID,
    keyID: process.env.APPLE_KEY_ID,
    privateKey: process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    callbackURL: process.env.APPLE_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const existingUser = await User.findOne({ appleId: profile.id });
        if (existingUser) {
            return done(null, existingUser);
        }
        const newUser = new User({
            appleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value || profile.email,
            profilePicture: profile.photos[0].value || profile.picture,
        });
        await newUser.save();
        done(null, newUser);
    } catch (error) {
        done(error, null);
    }
}));
*/



