import axios from 'axios';
import ScanHistory from '../models/ScanHistory.js';
import User from '../models/User.js';

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

    // Check for previous scan of same URL (within last 24h)
    const previousScan = await ScanHistory.findPreviousScan(userId, url.trim());
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

    if (previousScan && previousScan.createdAt > oneHourAgo) {
      // Return cached result (scanned within last hour)
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
        remainingScans: await user.getRemainingScans()
      });
    }

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
        risk_emoji: getRiskEmoji(mlResult.risk_level)
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
