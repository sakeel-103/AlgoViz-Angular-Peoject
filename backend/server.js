const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo'); // Added for MongoDB session store
const multer = require('multer');
const fs = require('fs');
const User = require('./models/User');
const Feedback = require('./models/Feedback');
const { validateSignup } = require('./middlewares/validation');
const http = require('http');
// const { Server } = require('socket.io'); // Commented out for Vercel deployment
const Review = require('./models/Review');
const Contact = require('./models/contact');
dotenv.config();

const app = express();
// const server = http.createServer(app); // Commented out for Vercel deployment
// const io = new Server(server); // Commented out for Vercel deployment

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// ==================== SERVER STARTUP ====================
// Start server only when running directly (not when imported)
if (require.main === module) {
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => { // Use app.listen instead of server.listen for local testing
        console.log(`Server running on port ${PORT}`);
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
        console.log('Shutting down gracefully...');
        await mongoose.connection.close();
        process.exit(0);
    });
}

// Export for Vercel
module.exports = app;
// ==================== END OF VERCEL CONFIG ====================

// ================== Session middleware setup ===================
app.use(session({
    secret: process.env.SESSION_SECRET || 'defaultSecret',
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ // Use MongoDB for session storage
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions'
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict'
    }
}));

// ======================== MongoDB connection Started =====================
mongoose.connect(process.env.MONGODB_URI, {
    maxPoolSize: 10, // Limit connection pool size for serverless
    serverSelectionTimeoutMS: 5000 // Timeout for server selection
})
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1); // Exit if connection fails to prevent crashes
    });
const upload = multer({ dest: 'uploads/' });

// ============== Socket.io connection used here handling for real-time updates =============
// Note: Socket.IO is commented out as it’s not supported in Vercel’s serverless environment.
// To use Socket.IO, deploy this part on a WebSocket-compatible platform (e.g., Heroku, AWS).
/*
io.on('connection', (socket) => {
    console.log('A user connected');
    socket.on('updateGraph', (data) => {
        socket.broadcast.emit('graphUpdated', data);
    });
    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });
});
*/

// ============== Signup route with improved validation ============
app.post('/api/signup', async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;
    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Please provide a valid email address' });
    }
    if (password.length < 8 || !/\d/.test(password) || !/[a-zA-Z]/.test(password)) {
        return res.status(400).json({
            message: 'Password must be at least 8 characters and contain at least one letter and one number'
        });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'Email already exists' });
        }
        // Create new user without manual password hashing
        const newUser = new User({ username, email, password }); // Let pre('save') hook handle hashing
        await newUser.save();
        res.status(201).json({
            message: 'User registered successfully',
            userId: newUser._id
        });
    } catch (error) {
        console.error('Signup error:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: 'Validation error', errors: error.errors });
        }
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// ============== Login route with improved validation ============
app.post('/api/login', async (req, res) => {
    const { email, username, password } = req.body;
    const loginIdentifier = email || username;

    if (!loginIdentifier || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email/username and password are required'
        });
    }

    try {
        const user = await User.findOne({
            $or: [
                { email: loginIdentifier },
                { username: loginIdentifier }
            ]
        });

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Use the comparePassword method from the User model
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Generate token
        const token = user.generateAuthToken();

        // Return user data without password
        const userData = {
            _id: user._id,
            username: user.username,
            email: user.email,
            token: token
        };

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: userData
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

// =================== Contact form ========================
app.post('/api/contact', async (req, res) => {
    console.log('Raw incoming data:', req.body);

    try {
        if (mongoose.connection.readyState !== 1) {
            console.error('MongoDB not connected! Current state:', mongoose.connection.readyState);
            throw new Error('Database not connected');
        }
        const { email, question, feedback = '', suggestion = '' } = req.body;
        if (!email || !question) {
            console.log('Validation failed - missing fields');
            return res.status(400).json({
                success: false,
                message: 'Email and question are required'
            });
        }
        const newContact = new Contact({
            email,
            question,
            feedback,
            suggestion
        });
        const savedContact = await newContact.save();
        const exists = await Contact.exists({ _id: savedContact._id });
        if (!exists) throw new Error('Document not found after save!');
        console.log('Successfully saved to DB:', savedContact);
        res.status(201).json({
            success: true,
            data: savedContact
        });

    } catch (error) {
        console.error('Full error:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: 'Validation error',
                errors: error.errors
            });
        }
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message,
            dbState: mongoose.connection.readyState,
            dbName: mongoose.connection.name
        });
    }
});

// ============== Add new feedback ================
app.post('/api/feedback', async (req, res) => {
    const { author, content } = req.body;
    if (!author || !content) {
        return res.status(400).json({ message: 'Author and content are required' });
    }

    try {
        const feedback = new Feedback({ author, content });
        await feedback.save();
        res.status(201).json({ message: 'Feedback saved successfully', feedback });
    } catch (error) {
        console.error('Error saving feedback:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ========== Update the feedback form in every steps if user wants ================
app.put('/api/feedback/:id', async (req, res) => {
    const { content } = req.body;
    try {
        const updatedFeedback = await Feedback.findByIdAndUpdate(
            req.params.id,
            { content },
            { new: true }
        );
        if (!updatedFeedback) {
            return res.status(404).json({ message: 'Feedback not found' });
        }
        res.status(200).json({ message: 'Feedback updated successfully', updatedFeedback });
    } catch (error) {
        console.error('Error updating feedback:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// =========== Delete the feedback ==========================
app.delete('/api/feedback/:id', async (req, res) => {
    try {
        const deletedFeedback = await Feedback.findByIdAndDelete(req.params.id);
        if (!deletedFeedback) {
            return res.status(404).json({ message: 'Feedback not found' });
        }
        res.status(200).json({ message: 'Feedback deleted successfully' });
    } catch (error) {
        console.error('Error deleting feedback:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===================== Global error handler ===============================
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Server error' });
});

// ====================== Review Page =============================================
const reviewUpload = multer({ dest: 'uploads/reviews/' });
app.get('/api/reviews', async (req, res) => {
    try {
        const reviews = await Review.find().sort({ createdAt: -1 });
        res.status(200).json(reviews);
    } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Here is Create new review
app.post('/api/reviews', async (req, res) => {
    const { author, content } = req.body;

    if (!author || !content) {
        return res.status(400).json({ message: 'Author and content are required' });
    }
    try {
        const review = new Review({ author, content });
        await review.save();
        res.status(201).json(review);
    } catch (error) {
        console.error('Error creating review:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ============= Add question to review ==============
app.post('/api/reviews/:reviewId/questions', reviewUpload.single('file'), async (req, res) => {
    const { author, content } = req.body;
    const { reviewId } = req.params;
    if (!author || !content) {
        return res.status(400).json({ message: 'Author and content are required' });
    }
    try {
        const review = await Review.findById(reviewId);
        if (!review) {
            return res.status(404).json({ message: 'Review not found' });
        }
        const newQuestion = {
            author,
            content,
            filePath: req.file ? req.file.path : null
        };
        review.questions.push(newQuestion);
        await review.save();
        res.status(201).json(review);
    } catch (error) {
        console.error('Error adding question:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ================== Add reply to questions ===========
app.post('/api/reviews/:reviewId/questions/:questionId/replies', async (req, res) => {
    const { author, content } = req.body;
    const { reviewId, questionId } = req.params;
    if (!author || !content) {
        return res.status(400).json({ message: 'Author and content are required' });
    }
    try {
        const review = await Review.findById(reviewId);
        if (!review) {
            return res.status(404).json({ message: 'Review not found' });
        }
        const question = review.questions.id(questionId);
        if (!question) {
            return res.status(404).json({ message: 'Question not found' });
        }
        question.replies.push({ author, content });
        await review.save();
        res.status(201).json(review);
    } catch (error) {
        console.error('Error adding reply:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== PROFILE MANAGEMENT ROUTES ====================
const jwt = require('jsonwebtoken');

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Unauthorized - Token missing' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const user = await User.findById(decoded._id);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
};

// Update username
app.put('/api/update-name', verifyToken, async (req, res) => {
    try {
        const { newName } = req.body;

        if (!newName || newName.trim().length < 3) {
            return res.status(400).json({
                success: false,
                message: 'Username must be at least 3 characters'
            });
        }

        // Check if username is already taken
        const existingUser = await User.findOne({ username: newName });
        if (existingUser && existingUser._id.toString() !== req.user._id.toString()) {
            return res.status(409).json({
                success: false,
                message: 'Username already taken'
            });
        }

        req.user.username = newName;
        await req.user.save();

        res.status(200).json({
            success: true,
            message: 'Username updated successfully',
            newUsername: req.user.username
        });

    } catch (error) {
        console.error('Update name error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update username',
            error: error.message
        });
    }
});

// Change password
app.put('/api/change-password', verifyToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Both passwords are required'
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters'
            });
        }

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, req.user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Update password (pre-save hook in model will hash it)
        req.user.password = newPassword;
        await req.user.save();

        res.status(200).json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to change password',
            error: error.message
        });
    }
});

// Delete account
app.delete('/api/delete-account', verifyToken, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({
                success: false,
                message: 'Password is required'
            });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, req.user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Incorrect password'
            });
        }

        await User.findByIdAndDelete(req.user._id);

        res.status(200).json({
            success: true,
            message: 'Account deleted successfully'
        });

    } catch (error) {
        console.error('Delete account error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete account',
            error: error.message
        });
    }
});

// ==================== END OF PROFILE ROUTES ====================