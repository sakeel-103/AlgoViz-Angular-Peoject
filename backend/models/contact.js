const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        lowercase: true,
        match: [/.+\@.+\..+/, 'Please enter a valid email']
    },
    question: {
        type: String,
        required: [true, 'Question is required'],
        minlength: [10, 'Question must be at least 10 characters']
    },
    feedback: {
        type: String,
        default: ''
    },
    suggestion: {
        type: String,
        default: ''
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true // Adds createdAt and updatedAt automatically
});

module.exports = mongoose.model('Contact', contactSchema);