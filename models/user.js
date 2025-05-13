const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },

    googleId: { type: String, unique: true },
    githubId: { type: String, unique: true },
    appleId: { type: String, unique: true },

    displayName: { type: String },
    profilePicture: { type: String },
    createdAt: { type: Date, default: Date.now },

})



module.exports = mongoose.model('User', userSchema);