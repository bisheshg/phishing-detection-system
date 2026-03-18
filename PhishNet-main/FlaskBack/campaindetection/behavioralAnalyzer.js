import ScanHistory from "../models/ScanHistory.js";

/**
 * Advanced Behavioral Analyzer for detecting Tier-1 adversarial patterns.
 */
export const analyzeBehavior = async (userId, fingerprint, ipAddress) => {
  const ONE_HOUR_AGO = new Date(Date.now() - 60 * 60 * 1000);
  const ONE_MINUTE_AGO = new Date(Date.now() - 60 * 1000);

  // 1. Calculate Scan Velocity (Aggregated by Fingerprint)
  const recentScansCount = await ScanHistory.countDocuments({
    fingerprint,
    createdAt: { $gte: ONE_MINUTE_AGO }
  });

  const scanVelocity = recentScansCount; // Scans per minute

  // 2. Multi-Channel Intent Extraction (Simulated)
  // Check if this fingerprint has been scanning many different domains in a short window
  const uniqueDomains = await ScanHistory.distinct("domain", {
    fingerprint,
    createdAt: { $gte: ONE_HOUR_AGO }
  });

  let threatActorLikelihood = 0;
  
  // High velocity = Suspicious automated extractor
  if (scanVelocity > 10) threatActorLikelihood += 40;
  if (scanVelocity > 30) threatActorLikelihood += 50;

  // Wide domain breadth = Pattern matching or probing
  if (uniqueDomains.length > 5) threatActorLikelihood += 20;
  if (uniqueDomains.length > 20) threatActorLikelihood += 30;

  // 3. Geo-Contextual Anomalies (Mocked for MVP, in production use IP-API)
  const geoContext = {
    country: "Unknown", // Placeholder for actual IP lookup
    isp: "Unknown",
    isProxy: false
  };

  return {
    scanVelocity,
    geoContext,
    threatActorLikelihood: Math.min(100, threatActorLikelihood)
  };
};
