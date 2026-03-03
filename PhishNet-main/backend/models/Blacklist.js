import mongoose from 'mongoose';

const blacklistSchema = new mongoose.Schema({
    // URL Information
    url: {
        type: String,
        required: true,
        trim: true,
        index: true
    },
    domain: {
        type: String,
        required: true,
        index: true
    },
    normalizedDomain: {
        type: String,  // Lowercase, no www, for fast lookup
        required: true,
        unique: true,
        index: true
    },

    // Classification
    category: {
        type: String,
        enum: ['phishing', 'malware', 'scam', 'spam', 'other'],
        default: 'phishing'
    },

    // Source tracking
    source: {
        type: String,
        enum: ['user_report', 'admin_manual', 'auto_detected', 'external_feed', 'ml_high_confidence'],
        required: true
    },

    // Validation & Reports
    reportsCount: {
        type: Number,
        default: 1,
        min: 0
    },
    reportedBy: [{
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        reportedAt: {
            type: Date,
            default: Date.now
        },
        evidence: String,
        ipAddress: String
    }],

    // Status & Verification
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'false_positive', 'expired', 'removed'],
        default: 'pending',
        index: true
    },
    verifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    verifiedAt: Date,

    // Timestamps
    addedDate: {
        type: Date,
        default: Date.now,
        index: true
    },
    expiresAt: {
        type: Date,
        index: true
    },
    lastSeenDate: Date,

    // Detection Details
    detectionMethod: {
        type: String,
        default: 'unknown'
    },
    mlConfidence: {
        type: Number,
        min: 0,
        max: 100
    },
    triggeredRules: [{
        rule: String,
        severity: String,
        description: String
    }],
    ensembleVoting: {
        phishing_votes: Number,
        legitimate_votes: Number,
        consensus_confidence: String
    },

    // Additional Metadata
    screenshot: String,
    pageTitle: String,
    targetBrand: String,
    pageContent: String,

    // Metrics & Analytics
    hitCount: {
        type: Number,
        default: 0,
        min: 0
    },
    lastHitDate: Date,
    blockCount: {
        type: Number,
        default: 0,
        min: 0
    },

    // Admin Notes
    adminNotes: String,
    reviewNotes: String,

    // False Positive Tracking
    falsePositiveReports: [{
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        reportedAt: {
            type: Date,
            default: Date.now
        },
        reason: String
    }]
}, {
    timestamps: true
});

// Indexes for fast lookup
blacklistSchema.index({ normalizedDomain: 1, status: 1 });
blacklistSchema.index({ addedDate: -1 });
blacklistSchema.index({ expiresAt: 1 });
blacklistSchema.index({ status: 1, category: 1 });
blacklistSchema.index({ 'reportedBy.userId': 1 });

// Virtual: is entry expired?
blacklistSchema.virtual('isExpired').get(function() {
    return this.expiresAt && this.expiresAt < new Date();
});

// Virtual: is entry active?
blacklistSchema.virtual('isActive').get(function() {
    return this.status === 'confirmed' && !this.isExpired;
});

// Static: normalize domain for consistent lookup
blacklistSchema.statics.normalizeDomain = function(url) {
    try {
        let domain = url.replace(/^https?:\/\//, '');
        domain = domain.split('/')[0];
        domain = domain.split('?')[0];
        domain = domain.split('#')[0];
        domain = domain.split(':')[0];
        domain = domain.replace(/^www\./, '');
        return domain.toLowerCase();
    } catch {
        return url.toLowerCase();
    }
};

// Static: check if URL is blacklisted
blacklistSchema.statics.isBlacklisted = async function(url) {
    try {
        const normalizedDomain = this.normalizeDomain(url);
        const entry = await this.findOne({
            normalizedDomain,
            status: 'confirmed',
            $or: [
                { expiresAt: { $exists: false } },
                { expiresAt: { $gt: new Date() } }
            ]
        });

        if (entry) {
            entry.hitCount += 1;
            entry.lastHitDate = new Date();
            await entry.save();
            return {
                is_blacklisted: true,
                entry,
                reason: entry.category,
                added_date: entry.addedDate,
                reports_count: entry.reportsCount
            };
        }
        return { is_blacklisted: false };
    } catch (error) {
        console.error('Blacklist check error:', error);
        return { is_blacklisted: false, error: error.message };
    }
};

// Instance: add a user report
blacklistSchema.methods.addReport = function(userId, evidence, ipAddress) {
    this.reportedBy.push({ userId, reportedAt: new Date(), evidence, ipAddress });
    this.reportsCount = this.reportedBy.length;
    return this.save();
};

// Instance: record a hit
blacklistSchema.methods.recordHit = function() {
    this.hitCount += 1;
    this.lastHitDate = new Date();
    return this.save();
};

// Instance: record a block
blacklistSchema.methods.recordBlock = function() {
    this.blockCount += 1;
    this.lastHitDate = new Date();
    return this.save();
};

// Pre-save: set 90-day expiry for confirmed entries
blacklistSchema.pre('save', function(next) {
    if (!this.expiresAt && this.status === 'confirmed') {
        this.expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    }
    if (this.domain && !this.normalizedDomain) {
        this.normalizedDomain = this.constructor.normalizeDomain(this.domain);
    }
    next();
});

const Blacklist = mongoose.model('Blacklist', blacklistSchema);
export default Blacklist;
