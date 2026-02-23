import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    name: {
      type: String,
      required: true,
    },
    phone: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isPremium: {
      type: Boolean,
      default: false
    },
    // Scan tracking
    totalScans: {
      type: Number,
      default: 0
    },
    lastScanDate: {
      type: Date,
      default: null
    },
    // Scan limits
    dailyScanLimit: {
      type: Number,
      default: function() {
        return this.isPremium ? 1000 : 50; // Premium: 1000/day, Free: 50/day
      }
    },
    // Premium metadata
    premiumExpiresAt: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

// Method to check if user has exceeded daily scan limit
UserSchema.methods.canScan = async function() {
  const ScanHistory = mongoose.model('ScanHistory');
  const todaysScans = await ScanHistory.getTodaysScanCount(this._id);

  const limit = this.isPremium ? 1000 : 50;
  return todaysScans < limit;
};

// Method to get remaining scans for today
UserSchema.methods.getRemainingScans = async function() {
  const ScanHistory = mongoose.model('ScanHistory');
  const todaysScans = await ScanHistory.getTodaysScanCount(this._id);

  const limit = this.isPremium ? 1000 : 50;
  return Math.max(0, limit - todaysScans);
};

// Method to increment total scan count
UserSchema.methods.incrementScanCount = async function() {
  this.totalScans += 1;
  this.lastScanDate = new Date();
  await this.save();
};

export default mongoose.model("User", UserSchema);