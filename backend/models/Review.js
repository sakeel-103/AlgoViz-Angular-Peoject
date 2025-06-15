const mongoose = require('mongoose');

const ReplySchema = new mongoose.Schema({
    author: String,
    content: String,
    createdAt: { type: Date, default: Date.now }
});

const QuestionSchema = new mongoose.Schema({
    author: String,
    content: String,
    filePath: String, // Store file path if uploaded
    replies: [ReplySchema],
    createdAt: { type: Date, default: Date.now }
});

const ReviewSchema = new mongoose.Schema({
    author: String,
    content: String,
    questions: [QuestionSchema],
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Review', ReviewSchema);