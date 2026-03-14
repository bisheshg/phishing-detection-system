import mongoose from "mongoose";

const ScanHistorySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    url: {
      type: String,
      required: true,
    },
    domain: {
      type: String,
      required: true,
      index: true,
    },
    prediction: {
      type: String,
      enum: ["Phishing", "Legitimate", "Suspicious"],
      required: true,
    },
    confidence: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    riskLevel: {
      type: String,
      enum: ["Safe", "Low", "Medium", "High", "Critical"],
      required: true,
    },
    safeToVisit: {
      type: Boolean,
      required: true,
    },
    isTrusted: {
      type: Boolean,
      default: false,
    },
    // Detailed results from ML models
    ensemble: {
      agreement: String,
      consensusProbability: Number,
      individualPredictions: mongoose.Schema.Types.Mixed,
      individualProbabilities: mongoose.Schema.Types.Mixed,
    },
    features: {
      type: mongoose.Schema.Types.Mixed,
    },
    boostReasons: [String],
    riskBoost: Number,
    baseProbability: Number,
    modelInfo: {
      detectionMethod: String,
      modelsUsed: String,
      f1Score: Number,
    },
    // Metadata
    scanDuration: {
      type: Number, // milliseconds
    },
    ipAddress: {
      type: String,
    },
    userAgent: {
      type: String,
    },
  },
  {
    timestamps: true,
    // Automatically create indexes
    autoIndex: true,
  }
);

// Compound index for user's recent scans
ScanHistorySchema.index({ userId: 1, createdAt: -1 });

// Index for domain lookup
ScanHistorySchema.index({ domain: 1, createdAt: -1 });

// Static method to get user's scan count for today
ScanHistorySchema.statics.getTodaysScanCount = async function(userId) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  return await this.countDocuments({
    userId,
    createdAt: { $gte: today }
  });
};

// Static method to get user's total scan count
ScanHistorySchema.statics.getTotalScanCount = async function(userId) {
  return await this.countDocuments({ userId });
};

// Static method to get recent scans for a user
ScanHistorySchema.statics.getRecentScans = async function(userId, limit = 10) {
  return await this.find({ userId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .select('-features -ensemble.individualPredictions -ensemble.individualProbabilities');
};

// Static method to get phishing URLs detected by user
ScanHistorySchema.statics.getPhishingScans = async function(userId, limit = 20) {
  return await this.find({
    userId,
    prediction: "Phishing"
  })
    .sort({ createdAt: -1 })
    .limit(limit)
    .select('url domain confidence riskLevel createdAt');
};

// Static method to check if URL was scanned before by this user
ScanHistorySchema.statics.findPreviousScan = async function(userId, url) {
  return await this.findOne({
    userId,
    url
  }).sort({ createdAt: -1 });
};

export default mongoose.model("ScanHistory", ScanHistorySchema);
