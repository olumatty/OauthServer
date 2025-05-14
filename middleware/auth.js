const jwt = require('jsonwebtoken');
const User = require('../models/user');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.JWT_SECRET, async (err, userpayload) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid token' });
            }
            
            try {
                const user = await User.findById(userpayload.id);
                if (!user) {
                    return res.status(404).json({ message: 'User not found' });
                }
                req.user = user;
                next();
            } catch (error) {
                console.error("Error fetching user from DB based on JWT:", error);
                return res.status(500).json({ message: 'Internal server error' });
            }
    });
    } else {
        return res.status(401).json({ message: 'Missing authorization header' });
    }
}

module.exports = authenticateToken;

