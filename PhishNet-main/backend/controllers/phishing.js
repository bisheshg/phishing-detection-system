import axios from 'axios';
import ScanHistory from '../models/ScanHistory.js';
import User from '../models/User.js';
import Blacklist from '../models/Blacklist.js';

// Flask ML service URL (use 127.0.0.1 to avoid IPv6 issues)
const FLASK_ML_URL = process.env.FLASK_ML_URL || 'http://127.0.0.1:5002';

// ==================== ANALYZE URL ====================
export const analyzeUrl = async (req, res, next) => {
  const startTime = Date.now();

  try {
    const { url } = req.body;
    const userId = req.user.id; // From JWT middleware

    // Validate URL
    if (!url || !url.trim()) {
      return res.status(400).json({
        success: false,
        message: "URL is required"
      });
    }

    // Get user and check scan limit
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    // Check if user can scan (daily limit)
    const canScan = await user.canScan();
    if (!canScan) {
      const limit = user.isPremium ? 1000 : 50;
      return res.status(429).json({
        success: false,
        message: `Daily scan limit reached (${limit} scans/day)`,
        upgradeMessage: user.isPremium
          ? "You've reached your premium limit. Please try again tomorrow."
          : "Upgrade to Premium for 1000 scans/day!",
        isPremium: user.isPremium,
        dailyLimit: limit
      });
    }

    // ── LAYER 0: Blacklist check ──────────────────────────────────────────
    // Runs BEFORE cache so a domain that was cached as "Legitimate" but later
    // blacklisted is always correctly blocked on the next request.
    try {
      const blacklistResult = await Blacklist.isBlacklisted(url.trim());

      if (blacklistResult.is_blacklisted) {
        const entry = blacklistResult.entry;
        console.log(`[BLACKLIST] Blocked: ${url.trim()} (${entry.category})`);

        const scanHistory = new ScanHistory({
          userId: user._id,
          url: url.trim(),
          domain: entry.normalizedDomain,
          prediction: 'Phishing',
          confidence: entry.mlConfidence || 100,
          riskLevel: 'Critical',
          safeToVisit: false,
          isTrusted: false,
          boostReasons: [`Blacklisted domain (${entry.category})`],
          riskBoost: 1,
          baseProbability: 1,
          modelInfo: { detectionMethod: 'Blacklist Match (Layer 0)', modelsUsed: 0 },
          scanDuration: Date.now() - startTime,
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('User-Agent'),
        });

        await scanHistory.save();
        await user.incrementScanCount();

        return res.status(200).json({
          success: true,
          message: "URL analyzed successfully",
          cached: false,
          data: {
            url: url.trim(),
            domain: entry.normalizedDomain,
            prediction: 'Phishing',
            confidence: entry.mlConfidence || 100,
            probability: (entry.mlConfidence || 100) / 100,
            base_probability: 1,
            risk_boost: 1,
            boost_reasons: [`Blacklisted domain — category: ${entry.category}`],
            safe_to_visit: false,
            is_trusted: false,
            risk_level: 'Critical',
            risk_emoji: '🔴',
            risk_color: 'red',
            detection_source: 'blacklist',
            blacklist_info: {
              category: entry.category,
              target_brand: entry.targetBrand || null,
              added_date: entry.addedDate,
              reports_count: entry.reportsCount,
              detection_method: entry.detectionMethod,
            },
            model_info: {
              detection_method: 'Blacklist Match (Layer 0 — instant)',
              models_used: 0,
              rules_checked: 0,
            },
            threshold_used: 0.5,
            timestamp: new Date().toISOString(),
            scanId: scanHistory._id,
          },
          userInfo: {
            isPremium: user.isPremium,
            remainingScans: await user.getRemainingScans(),
            totalScans: user.totalScans,
          },
        });
      }
    } catch (blacklistErr) {
      // Non-fatal: if blacklist check fails, fall through to cache/ML
      console.error('[BLACKLIST] Check error (falling through):', blacklistErr.message);
    }
    // ─────────────────────────────────────────────────────────────────────

    // ── Cache check ───────────────────────────────────────────────────────
    // Only serve cache for:
    //   1. Confirmed phishing results (unlikely to flip to legitimate)
    //   2. High-confidence legitimate results (≥45%) — trusted, well-known sites
    // Borderline "Legitimate" results (confidence <45%) are re-analyzed fresh
    // so that rule engine or model updates are reflected immediately.
    const previousScan = await ScanHistory.findPreviousScan(userId, url.trim());
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const isBorderlineLegitimate =
      previousScan &&
      previousScan.prediction === 'Legitimate' &&
      previousScan.confidence < 45;

    if (previousScan && previousScan.createdAt > oneHourAgo && !isBorderlineLegitimate) {
      return res.status(200).json({
        success: true,
        message: "Returning cached result (scanned recently)",
        cached: true,
        data: {
          url: previousScan.url,
          domain: previousScan.domain,
          prediction: previousScan.prediction,
          confidence: previousScan.confidence,
          risk_level: previousScan.riskLevel,
          risk_emoji: getRiskEmoji(previousScan.riskLevel),
          safe_to_visit: previousScan.safeToVisit,
          is_trusted: previousScan.isTrusted,
          ensemble: previousScan.ensemble,
          features: previousScan.features,
          boost_reasons: previousScan.boostReasons,
          risk_boost: previousScan.riskBoost,
          base_probability: previousScan.baseProbability,
          model_info: previousScan.modelInfo,
          threshold_used: 0.5,
          timestamp: previousScan.createdAt,
          scanId: previousScan._id
        },
        userInfo: {
          isPremium: user.isPremium,
          remainingScans: await user.getRemainingScans(),
          totalScans: user.totalScans
        }
      });
    }

    // Borderline result was cached — delete it so the fresh result replaces it cleanly
    if (isBorderlineLegitimate) {
      await ScanHistory.findByIdAndDelete(previousScan._id);
      console.log(`[CACHE] Invalidated borderline scan ${previousScan._id} (${previousScan.confidence}% confidence) — re-analyzing`);
    }
    // ─────────────────────────────────────────────────────────────────────

    // Call Flask ML service
    let mlResult;
    try {
      const flaskResponse = await axios.post(
        `${FLASK_ML_URL}/analyze_url`,
        { url: url.trim() },
        {
          headers: { 'Content-Type': 'application/json' },
          timeout: 30000 // 30 second timeout
        }
      );

      mlResult = flaskResponse.data;
    } catch (flaskError) {
      console.error('Flask ML service error:', flaskError.message);

      // Check if Flask service is down
      if (flaskError.code === 'ECONNREFUSED') {
        return res.status(503).json({
          success: false,
          message: "Phishing detection service is temporarily unavailable",
          error: "ML_SERVICE_DOWN"
        });
      }

      return res.status(500).json({
        success: false,
        message: "Failed to analyze URL",
        error: flaskError.response?.data?.error || flaskError.message
      });
    }

    // Save scan to database
    const scanHistory = new ScanHistory({
      userId: user._id,
      url: mlResult.url,
      domain: mlResult.domain,
      prediction: mlResult.prediction,
      confidence: mlResult.confidence,
      riskLevel: mlResult.risk_level,
      safeToVisit: mlResult.safe_to_visit,
      isTrusted: mlResult.is_trusted || false,
      ensemble: {
        agreement: mlResult.ensemble?.agreement,
        consensusProbability: mlResult.ensemble?.consensus_probability,
        individualPredictions: mlResult.ensemble?.individual_predictions,
        individualProbabilities: mlResult.ensemble?.individual_probabilities,
      },
      features: mlResult.features,
      boostReasons: mlResult.boost_reasons,
      riskBoost: mlResult.risk_boost,
      baseProbability: mlResult.base_probability,
      modelInfo: {
        detectionMethod: mlResult.model_info?.detection_method,
        modelsUsed: mlResult.model_info?.models_used,
        f1Score: mlResult.model_info?.f1_score,
      },
      scanDuration: Date.now() - startTime,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
    });

    await scanHistory.save();

    // Update user's scan count
    await user.incrementScanCount();

    // ── AUTO-PROMOTE to Blacklist ───────────────────────────────────────────
    // Any phishing prediction on an untrusted domain is immediately added to
    // the confirmed blacklist so future scans are blocked at Layer 0 instantly.
    let autoBlacklisted = false;
    if (mlResult.prediction === 'Phishing' && !mlResult.is_trusted) {
      try {
        const normalizedDomain = Blacklist.normalizeDomain(mlResult.url || url.trim());
        const existing = await Blacklist.findOne({ normalizedDomain });

        if (!existing) {
          await Blacklist.create({
            url: url.trim(),
            domain: normalizedDomain,
            normalizedDomain,
            category: 'phishing',
            source: 'ml_high_confidence',
            status: 'confirmed',
            mlConfidence: mlResult.confidence,
            detectionMethod: mlResult.model_info?.detection_method || 'ML Ensemble',
            reportsCount: 0,
            reportedBy: [],
          });
          autoBlacklisted = true;
          console.log(`[BLACKLIST] Auto-added: ${normalizedDomain} (${mlResult.confidence}% confidence, ${mlResult.detection_source || 'ml'})`);
        } else if (existing.status !== 'confirmed') {
          existing.status = 'confirmed';
          existing.mlConfidence = mlResult.confidence;
          existing.detectionMethod = mlResult.model_info?.detection_method || 'ML Ensemble';
          await existing.save();
          autoBlacklisted = true;
          console.log(`[BLACKLIST] Auto-confirmed: ${normalizedDomain} (${mlResult.confidence}% confidence)`);
        }
      } catch (blErr) {
        // Non-fatal — log and continue
        console.error('[BLACKLIST] Auto-promote error:', blErr.message);
      }
    }
    // ─────────────────────────────────────────────────────────────────────────

    // Get remaining scans
    const remainingScans = await user.getRemainingScans();

    // Return result
    res.status(200).json({
      success: true,
      message: "URL analyzed successfully",
      cached: false,
      data: {
        ...mlResult,
        scanId: scanHistory._id,
        risk_emoji: getRiskEmoji(mlResult.risk_level),
        auto_blacklisted: autoBlacklisted
      },
      userInfo: {
        isPremium: user.isPremium,
        remainingScans,
        totalScans: user.totalScans
      }
    });

  } catch (error) {
    console.error('Analyze URL error:', error);
    next(error);
  }
};

// ==================== GET SCAN HISTORY ====================
export const getScanHistory = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { limit = 20, page = 1 } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const scans = await ScanHistory.find({ userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('-features -ensemble.individualPredictions -ensemble.individualProbabilities');

    const total = await ScanHistory.countDocuments({ userId });

    res.status(200).json({
      success: true,
      data: scans,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get scan history error:', error);
    next(error);
  }
};

// ==================== GET PHISHING DETECTIONS ====================
export const getPhishingDetections = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { limit = 20 } = req.query;

    const phishingScans = await ScanHistory.getPhishingScans(userId, parseInt(limit));

    res.status(200).json({
      success: true,
      count: phishingScans.length,
      data: phishingScans
    });

  } catch (error) {
    console.error('Get phishing detections error:', error);
    next(error);
  }
};

// ==================== GET SCAN STATISTICS ====================
export const getScanStatistics = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);

    const totalScans = await ScanHistory.getTotalScanCount(userId);
    const todaysScans = await ScanHistory.getTodaysScanCount(userId);
    const remainingScans = await user.getRemainingScans();

    const phishingCount = await ScanHistory.countDocuments({
      userId,
      prediction: "Phishing"
    });

    const legitimateCount = await ScanHistory.countDocuments({
      userId,
      prediction: "Legitimate"
    });

    // Get risk distribution
    const riskDistribution = await ScanHistory.aggregate([
      { $match: { userId: user._id } },
      { $group: { _id: "$riskLevel", count: { $sum: 1 } } }
    ]);

    res.status(200).json({
      success: true,
      data: {
        totalScans,
        todaysScans,
        remainingScans,
        dailyLimit: user.isPremium ? 1000 : 50,
        phishingCount,
        legitimateCount,
        phishingRate: totalScans > 0 ? ((phishingCount / totalScans) * 100).toFixed(1) : 0,
        riskDistribution: riskDistribution.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        isPremium: user.isPremium,
        lastScanDate: user.lastScanDate
      }
    });

  } catch (error) {
    console.error('Get scan statistics error:', error);
    next(error);
  }
};

// ==================== GET SINGLE SCAN ====================
export const getScan = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { scanId } = req.params;

    const scan = await ScanHistory.findOne({
      _id: scanId,
      userId
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found"
      });
    }

    res.status(200).json({
      success: true,
      data: scan
    });

  } catch (error) {
    console.error('Get scan error:', error);
    next(error);
  }
};

// ==================== DELETE SCAN ====================
export const deleteScan = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { scanId } = req.params;

    const scan = await ScanHistory.findOneAndDelete({
      _id: scanId,
      userId
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found"
      });
    }

    res.status(200).json({
      success: true,
      message: "Scan deleted successfully"
    });

  } catch (error) {
    console.error('Delete scan error:', error);
    next(error);
  }
};

// ==================== REPORT PHISHING URL ====================
export const reportPhishing = async (req, res, next) => {
  try {
    const { url, evidence, targetBrand } = req.body;
    const userId = req.user.id;

    if (!url || !url.trim()) {
      return res.status(400).json({ success: false, message: 'URL is required' });
    }

    const normalizedDomain = Blacklist.normalizeDomain(url.trim());

    // Check if already in blacklist
    const existing = await Blacklist.findOne({ normalizedDomain });

    if (existing) {
      if (existing.status === 'confirmed') {
        return res.status(200).json({
          success: true,
          message: 'This domain is already confirmed in our blacklist.',
          alreadyBlacklisted: true,
          status: 'confirmed',
        });
      }

      // Add this user's report to existing pending entry
      const alreadyReported = existing.reportedBy.some(r => r.userId?.toString() === userId);
      if (!alreadyReported) {
        await existing.addReport(userId, evidence, req.ip);
      }

      // Auto-confirm after 3+ independent reports
      if (existing.reportsCount >= 3 && existing.status === 'pending') {
        existing.status = 'confirmed';
        await existing.save();
        console.log(`[BLACKLIST] Auto-confirmed: ${normalizedDomain} (${existing.reportsCount} reports)`);
      }

      return res.status(200).json({
        success: true,
        message: 'Your report has been recorded. Thank you for helping keep the web safe!',
        reportsCount: existing.reportsCount,
        status: existing.status,
      });
    }

    // New entry — pending review
    const newEntry = await Blacklist.create({
      url: url.trim(),
      domain: normalizedDomain,
      normalizedDomain,
      category: 'phishing',
      source: 'user_report',
      status: 'pending',
      targetBrand: targetBrand || null,
      reportedBy: [{ userId, reportedAt: new Date(), evidence, ipAddress: req.ip }],
      reportsCount: 1,
    });

    console.log(`[BLACKLIST] New report: ${normalizedDomain} by user ${userId}`);

    return res.status(201).json({
      success: true,
      message: 'URL reported successfully. Our team will review it shortly.',
      reportId: newEntry._id,
      status: 'pending',
    });

  } catch (error) {
    console.error('Report phishing error:', error);
    next(error);
  }
};

// ==================== REMOVE FROM BLACKLIST (FALSE POSITIVE) ====================
export const removeFromBlacklist = async (req, res, next) => {
  try {
    const { url } = req.body;

    if (!url || !url.trim()) {
      return res.status(400).json({ success: false, message: "URL is required" });
    }

    const normalizedDomain = Blacklist.normalizeDomain(url.trim());
    const entry = await Blacklist.findOne({ normalizedDomain });

    if (!entry) {
      return res.status(404).json({
        success: false,
        message: "This domain is not in the blacklist"
      });
    }

    entry.status = 'false_positive';
    entry.reviewNotes = `Marked as false positive by user ${req.user.id} on ${new Date().toISOString()}`;
    await entry.save();

    console.log(`[BLACKLIST] Removed (false positive): ${normalizedDomain} by user ${req.user.id}`);

    res.status(200).json({
      success: true,
      message: `${normalizedDomain} has been removed from the blacklist and marked as a false positive.`
    });

  } catch (error) {
    console.error('Remove from blacklist error:', error);
    next(error);
  }
};

// ==================== HELPER FUNCTIONS ====================
function getRiskEmoji(riskLevel) {
  const emojiMap = {
    'Critical': '🔴',
    'High': '🟠',
    'Medium': '🟡',
    'Low': '🟢',
    'Safe': '✅'
  };
  return emojiMap[riskLevel] || '⚪';
}
