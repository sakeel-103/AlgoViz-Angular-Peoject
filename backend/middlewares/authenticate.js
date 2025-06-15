// Middleware for protected routes
const authenticateSession = (req, res, next) => {
    if (req.session.userId) {
        next(); // User is authenticated, proceed to the next middleware/route
    } else {
        res.status(401).json({ message: 'Unauthorized: Please log in.' }); // Unauthorized if no user session exists
    }
};

module.exports = authenticateSession;