const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const reportSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: uuidv4
    },
    fileName: {
        type: String,
        required: true
    },
    fileHash: {
        type: String,
        required: false // For future use if we want deduplication
    },
    score: {
        type: Number,
        required: true
    },
    riskLevel: {
        type: String,
        enum: ['safe', 'low', 'medium', 'high', 'critical'],
        required: true
    },
    analyzedAt: {
        type: Date,
        default: Date.now
    },
    findings: [{
        check: String,
        severity: {
            type: String,
            enum: ['low', 'medium', 'high', 'critical']
        },
        message: String
    }],
    metadata: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
    },
    aiScore: {
        dimensions: {
            type: Map,
            of: mongoose.Schema.Types.Mixed
        },
        total: Number,
        riskLabel: String
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Report', reportSchema);
