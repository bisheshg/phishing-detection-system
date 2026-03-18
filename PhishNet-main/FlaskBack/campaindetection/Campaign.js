import mongoose from "mongoose";

const CampaignSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      default: () => `Campaign-${Math.random().toString(36).substr(2, 9)}`
    },
    signatures: {
      html_hash: { type: String, index: true },
      server_ip: { type: String, index: true },
      semantic_embedding: { type: [Number], index: false },
      vectors: {
        qr_hash: String, // For QR-based "Quishing"
        sms_fingerprint: String, // For Smishing patterns
      },
    },
    status: {
      type: String,
      enum: ["Active", "Inactive", "Mitigated"],
      default: "Active"
    },
    threatLevel: {
      type: String,
      enum: ["High", "Critical"],
      default: "High"
    },
    detectedUrls: [{
      url: String,
      scannedAt: { type: Date, default: Date.now }
    }],
    totalHits: {
      type: Number,
      default: 1
    },
    firstSeen: {
      type: Date,
      default: Date.now
    },
    lastSeen: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

// Global campaign dashboard feed requires quick access to active campaigns
CampaignSchema.index({ status: 1, lastSeen: -1 });

export default mongoose.model("Campaign", CampaignSchema);
