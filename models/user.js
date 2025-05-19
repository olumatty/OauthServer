const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const {v4: uuidv4} = require('uuid');

const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: function() {
            return !this.googleId ;
        }, 
        unique: true,
        sparse: true,
     },
    password: {
         type: String, 
         required: function() {
            return !this.googleId;
        },
    },
    email: { 
        type: String,
        required: true,
        unique: true 
    },
    userId : {
        type:String,
        default: uuidv4,
        unique: true,
        required:true,
    },

    googleId: { type: String, unique: true, sparse: true },

    displayName: { type: String },
    profilePicture: { type: String },
    createdAt: { type: Date, default: Date.now },
})

userSchema.pre('save', function(next) {
    if (!this.isModified('password')) return next();
    const salt = bcrypt.genSaltSync(10);
    this.password = bcrypt.hashSync(this.password, salt);
    next();;
});

module.exports = mongoose.model('User', userSchema);