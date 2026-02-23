import express from "express";
import {
  analyzeUrl,
  getScanHistory,
  getPhishingDetections,
  getScanStatistics,
  getScan,
  deleteScan
} from "../controllers/phishing.js";
import { verifyToken } from "../utils/verifyToken.js";

const router = express.Router();

// All phishing routes require authentication
router.use(verifyToken);

// POST /api/phishing/analyze - Analyze a URL for phishing
router.post("/analyze", analyzeUrl);

// GET /api/phishing/history - Get user's scan history (paginated)
router.get("/history", getScanHistory);

// GET /api/phishing/detections - Get phishing URLs detected by user
router.get("/detections", getPhishingDetections);

// GET /api/phishing/statistics - Get scan statistics for user
router.get("/statistics", getScanStatistics);

// GET /api/phishing/:scanId - Get single scan details
router.get("/:scanId", getScan);

// DELETE /api/phishing/:scanId - Delete a scan from history
router.delete("/:scanId", deleteScan);

export default router;
