const mongoose = require('mongoose');


const userSchema = new mongoose.Schema({
    username: { 
        type: String, 

        required: function() {
            return !this.googleId && !this.githubId && !this.appleId;
        }, 
        unique: true,
        sparse: true,

     },
    password: {
         type: String, 
         required: function() {
            return !this.googleId && !this.githubId && !this.appleId;
        },
    },
    email: { 
        type: String,
        required: true,
        unique: true 
    },

    googleId: { type: String, unique: true, sparse: true },
    githubId: { type: String, unique: true, sparse: true },
    appleId: { type: String, unique: true, sparse: true },

    displayName: { type: String },
    profilePicture: { type: String },
    createdAt: { type: Date, default: Date.now },

})

module.exports = mongoose.model('User', userSchema);