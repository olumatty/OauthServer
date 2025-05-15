const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const generateToken = (user)=> {
    const payload ={
        id: user._id,
        username: user.username,
        email: user.email

        }
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' })
}

module.exports = generateToken;