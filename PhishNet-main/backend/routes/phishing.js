import express from "express";
import {
  analyzeUrl,
  reportPhishing,
  getScanHistory,
  getPhishingDetections,
  getScanStatistics,
  getScan,
  deleteScan,
  removeFromBlacklist,
  getCampaigns,
  deleteCampaign
} from "../controllers/phishing.js";
import { verifyToken } from "../utils/verifyToken.js";

const router = express.Router();

// All phishing routes require authentication
router.use(verifyToken);

// POST /api/phishing/analyze - Analyze a URL for phishing
router.post("/analyze", analyzeUrl);

// POST /api/phishing/report - Report a URL as phishing
router.post("/report", reportPhishing);

// GET /api/phishing/history - Get user's scan history (paginated)
router.get("/history", getScanHistory);

// GET /api/phishing/detections - Get phishing URLs detected by user
router.get("/detections", getPhishingDetections);

// GET /api/phishing/statistics - Get scan statistics for user
router.get("/statistics", getScanStatistics);

// GET /api/phishing/campaigns - Get active threat campaigns
router.get("/campaigns", getCampaigns);

// DELETE /api/phishing/campaigns/:campaignId - Remove a false-positive campaign
router.delete("/campaigns/:campaignId", deleteCampaign);

// DELETE /api/phishing/blacklist/remove - Mark a blacklisted URL as false positive
// (must be defined BEFORE /:scanId to avoid Express treating "blacklist" as a scan ID)
router.delete("/blacklist/remove", removeFromBlacklist);

// GET /api/phishing/:scanId - Get single scan details
router.get("/:scanId", getScan);

// DELETE /api/phishing/:scanId - Delete a scan from history
router.delete("/:scanId", deleteScan);

export default router;
