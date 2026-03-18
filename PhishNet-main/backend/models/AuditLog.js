import mongoose from "mongoose";

const AuditLogSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
    },
    ipAddress: String,
    fingerprint: String,
    severity: {
      type: String,
      enum: ["Info", "Warning", "Critical"],
      default: "Info",
    },
    resourceId: mongoose.Schema.Types.ObjectId, // ID of the impacted resource (e.g., Campaign, User)
    resourceType: String,
  },
  {
    timestamps: true,
  }
);

// TTL index to automatically prune old logs after 90 days (Operational Hygiene)
AuditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 7776000 });

export default mongoose.model("AuditLog", AuditLogSchema);
