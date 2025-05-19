const jwt = require('jsonwebtoken');


const authenticateToken = async (req, res, next) => {

    let token = req.header.authorization?.split(' ')[1];

    if(token){
        console.log('Using token from Authorization user')
    }

    else if (req.cookies?.token){
        token = req.cookies.token;
        console.log("Using token from cookie.");
      } else {
        console.log("Token not found in header or cookie.");
      }

      if (req.path.includes('/api/auth/login') || 
      req.path.includes('/api/auth/register') || 
      req.path.includes('/api/auth/google')) {
        return next();
      }
      
      if (!token) {
        console.log('No token provided, sending 401');
        return res.status(401).json({ message: 'No token provided' });
      }
      
      try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        console.log('Token decoded:', decoded); 
        req.user = decoded;
        next();
      } catch (error) {
        console.error('Token verification error:', error.message);
        return res.status(401).json({ message: 'Invalid or expired token' });
      }
    

    }

module.exports = authenticateToken;
