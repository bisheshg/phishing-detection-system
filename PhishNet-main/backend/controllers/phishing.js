import axios from 'axios';
import ScanHistory from '../models/ScanHistory.js';
import User from '../models/User.js';
import Blacklist from '../models/Blacklist.js';
import Campaign from '../models/Campaign.js';
import AuditLog from '../models/AuditLog.js';
import { analyzeBehavior } from '../middleware/behavioralAnalyzer.js';
import { getIo } from '../utils/socket.js';

// Flask ML service URL (use 127.0.0.1 to avoid IPv6 issues)
const FLASK_ML_URL = process.env.FLASK_ML_URL || 'http://127.0.0.1:5002';

// In-flight deduplication: if two requests for the same URL arrive before
// the first one finishes (e.g. React StrictMode double-mount), the second
// awaits the first result instead of making a duplicate Flask call.
const _inFlightScans = new Map(); // url → Promise<responsePayload>

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

    // Scan limit removed — unlimited scans for all users

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
            remainingScans: 9999,
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
    // Re-scan "Suspicious" results on trusted domains — these are often false positives
    // from the hosted-content heuristic on legitimate platforms (claude.ai, docs.google.com)
    const isBorderlineSuspicious =
      previousScan &&
      previousScan.prediction === 'Suspicious' &&
      previousScan.isTrusted === true;

    if (previousScan && previousScan.createdAt > oneHourAgo && !isBorderlineLegitimate && !isBorderlineSuspicious) {
      return res.status(200).json({
        success: true,
        message: "Returning cached result (scanned recently)",
        cached: true,
        data: {
          url: previousScan.url,
          domain: previousScan.domain,
          prediction: previousScan.prediction,
          confidence: previousScan.confidence,
          probability: previousScan.baseProbability,
          base_probability: previousScan.baseProbability,
          risk_level: previousScan.riskLevel,
          risk_emoji: getRiskEmoji(previousScan.riskLevel),
          risk_color: previousScan.riskLevel === 'Critical' || previousScan.riskLevel === 'High' ? 'red' : previousScan.riskLevel === 'Medium' ? 'orange' : 'lightgreen',
          safe_to_visit: previousScan.safeToVisit,
          is_trusted: previousScan.isTrusted,
          ensemble: previousScan.ensemble,
          features: previousScan.features,
          boost_reasons: previousScan.boostReasons,
          risk_boost: previousScan.riskBoost,
          model_info: previousScan.modelInfo,
          detection_source: previousScan.detectionSource || 'ml_ensemble',
          threshold_used: 0.63,
          timestamp: previousScan.createdAt,
          scanId: previousScan._id,
          auto_blacklisted: false,
          campaign_info: null,
          campaign_match: null,
        },
        userInfo: {
          isPremium: user.isPremium,
          remainingScans: 9999,
          totalScans: user.totalScans
        }
      });
    }

    // Borderline result was cached — delete it so the fresh result replaces it cleanly
    if (isBorderlineLegitimate || isBorderlineSuspicious) {
      await ScanHistory.findByIdAndDelete(previousScan._id);
      console.log(`[CACHE] Invalidated stale scan ${previousScan._id} (${previousScan.prediction}, trusted=${previousScan.isTrusted}) — re-analyzing`);
    }
    // ─────────────────────────────────────────────────────────────────────

    // ── IN-FLIGHT DEDUP ──────────────────────────────────────────────────────
    // If a scan for this URL is already in progress, wait for its result.
    const _dedupKey = url.trim().toLowerCase();
    if (_inFlightScans.has(_dedupKey)) {
      console.log(`[DEDUP] Returning in-flight result for: ${_dedupKey}`);
      const payload = await _inFlightScans.get(_dedupKey);
      return res.status(200).json(payload ?? { success: false, message: 'Duplicate scan failed' });
    }
    let _resolveInFlight;
    _inFlightScans.set(_dedupKey, new Promise(r => { _resolveInFlight = r; }));
    // ─────────────────────────────────────────────────────────────────────────

    // Call Flask ML service
    let mlResult;
    try {
      const flaskResponse = await axios.post(
        `${FLASK_ML_URL}/analyze_url`,
        { url: url.trim() },
        {
          headers: { 'Content-Type': 'application/json' },
          timeout: 90000 // 90s — pipeline parallel after parallelizing domain metadata
        }
      );

      mlResult = flaskResponse.data;

      // ── Phase A: Campaign lookup — check before verdict is finalised ─────
      // If this URL's infrastructure fingerprint (html_hash or server_ip) matches
      // an existing Active campaign, override the verdict to Phishing/Critical
      // regardless of what the ML models said. A URL on a known phishing server
      // is phishing even when the page looks "clean" to the ML.
      try {
        const sig = mlResult.campaign_signature;
        if (sig) {
          const sigQueries = [];
          if (sig.html_hash) sigQueries.push({ 'signatures.html_hash': sig.html_hash });
          // Skip IP match for 'unknown' and 'shared_cdn' — shared_cdn means the URL
          // is hosted on Vercel/Netlify/GitHub Pages where all sites share the same
          // CDN IP pool. Matching on that IP would cross-contaminate unrelated sites.
          if (sig.server_ip && sig.server_ip !== 'unknown' && sig.server_ip !== 'shared_cdn') {
            sigQueries.push({ 'signatures.server_ip': sig.server_ip });
          }

          if (sigQueries.length > 0) {
            const existingCampaign = await Campaign.findOne({ status: 'Active', $or: sigQueries });
            if (existingCampaign) {
              const campaignMatchInfo = {
                id:          existingCampaign._id,
                name:        existingCampaign.name,
                totalHits:   existingCampaign.totalHits,
                threatLevel: existingCampaign.threatLevel,
                firstSeen:   existingCampaign.firstSeen,
                lastSeen:    existingCampaign.lastSeen,
              };
              // Override verdict — known phishing campaign infrastructure detected
              mlResult = {
                ...mlResult,
                prediction:       'Phishing',
                safe_to_visit:    false,
                risk_level:       campaignMatchInfo.totalHits >= 5 ? 'Critical' : 'High',
                confidence:       Math.max(mlResult.confidence || 0, 90),
                probability:      Math.max(mlResult.probability || 0, 0.90),
                detection_source: 'campaign_correlation',
                campaign_match:   campaignMatchInfo,
              };
              console.log(`[CAMPAIGN] Verdict overridden → Phishing (campaign: ${campaignMatchInfo.id}, hits: ${campaignMatchInfo.totalHits})`);
            }
          }
        }
      } catch (phaseAErr) {
        console.error('[CAMPAIGN] Phase A lookup error (non-fatal):', phaseAErr.message);
      }
      // ─────────────────────────────────────────────────────────────────────

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

    // ── Hosted-content risk flag ─────────────────────────────────────────
    // Trusted domain but ML unanimously phishing — attacker may be hosting
    // phishing content inside a legitimate platform (e.g. Google Docs/Drawings).
    // We do NOT override the verdict (too many false positives on chat/app URLs),
    // but set a flag so the UI can display an informational warning card.
    // Only flag hosted-content risk for actual content-hosting platforms (Drive, Dropbox, etc.)
    // NOT for core service subdomains like scholar.google.com or maps.google.com.
    const CONTENT_HOSTING_DOMAINS = [
      'docs.google.com', 'drive.google.com', 'sites.google.com',
      'storage.googleapis.com', 'dropbox.com', 'onedrive.live.com',
      'sharepoint.com', 'github.io', 'netlify.app', 'vercel.app',
      'web.app', 'firebaseapp.com', 's3.amazonaws.com', 'notion.site',
    ];
    const urlDomain = mlResult.domain || '';
    const isContentHost = CONTENT_HOSTING_DOMAINS.some(
      d => urlDomain === d || urlDomain.endsWith('.' + d)
    );
    const hostedContentRisk =
      isContentHost &&
      (mlResult.base_probability || 0) >= 0.90 &&
      mlResult.ensemble?.voting?.phishing_votes === mlResult.ensemble?.voting?.total_models;
    if (hostedContentRisk) {
      mlResult = { ...mlResult, hosted_content_risk: true };
      console.log(`[HOSTED-RISK] Trusted domain with unanimous ML phishing (${(mlResult.base_probability * 100).toFixed(1)}%) — flagged for UI: ${url.trim()}`);
    }
    // ─────────────────────────────────────────────────────────────────────

    // ── Behavioral analysis ───────────────────────────────────────────────
    const fingerprint = req.body.fingerprint || req.headers['x-fingerprint'] || 'unknown';
    let behaviorResult = { scanVelocity: 0, geoContext: { country: 'Unknown', isp: 'Unknown', isProxy: false }, threatActorLikelihood: 0 };
    try {
      behaviorResult = await analyzeBehavior(req.user.id, fingerprint, req.ip);
    } catch (behaviorErr) {
      console.error('[BEHAVIOR] Analysis error (non-fatal):', behaviorErr.message);
    }
    // ─────────────────────────────────────────────────────────────────────

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
      fingerprint,
      isOutlier: mlResult.is_outlier || false,
      behavioralContext: {
        scanVelocity: behaviorResult.scanVelocity,
        geoContext: behaviorResult.geoContext,
        threatActorLikelihood: behaviorResult.threatActorLikelihood,
      },
    });

    await scanHistory.save();

    // ── Campaign correlation (phishing detections only) ───────────────────
    let campaignId = null;
    let campaignInfo = null;   // ← surfaced to frontend
    if (mlResult.prediction === 'Phishing' && mlResult.campaign_signature) {
      try {
        const sig = mlResult.campaign_signature;
        const phaseBQueries = [];
        if (sig.html_hash) phaseBQueries.push({ 'signatures.html_hash': sig.html_hash });
        // Skip shared_cdn/unknown IPs — same reason as Phase A: shared CDN IPs
        // would incorrectly merge unrelated sites into the same campaign.
        if (sig.server_ip && sig.server_ip !== 'unknown' && sig.server_ip !== 'shared_cdn') {
          phaseBQueries.push({ 'signatures.server_ip': sig.server_ip });
        }
        let campaign = phaseBQueries.length > 0
          ? await Campaign.findOne({ status: 'Active', $or: phaseBQueries })
          : null;

        const isNew = !campaign;
        if (!campaign) {
          campaign = new Campaign({
            signatures: {
              html_hash: sig.html_hash,
              server_ip: sig.server_ip,
              semantic_embedding: sig.semantic_embedding || [],
            },
            detectedUrls: [{ url: url.trim() }],
            totalHits: 1,
            threatLevel: mlResult.risk_level === 'Critical' ? 'Critical' : 'High',
          });
        } else {
          campaign.detectedUrls.push({ url: url.trim() });
          campaign.totalHits += 1;
          campaign.lastSeen = new Date();
        }
        await campaign.save();
        campaignId = campaign._id;
        campaignInfo = {
          id:          campaign._id,
          name:        campaign.name,
          totalHits:   campaign.totalHits,
          threatLevel: campaign.threatLevel,
          firstSeen:   campaign.firstSeen,
          lastSeen:    campaign.lastSeen,
          isNew,       // true = campaign was just created by this scan
        };
        console.log(`[CAMPAIGN] ${isNew ? 'New' : 'Updated'} campaign ${campaign._id} — hits: ${campaign.totalHits}`);
      } catch (campErr) {
        console.error('[CAMPAIGN] Correlation error (non-fatal):', campErr.message);
      }
    }
    // ─────────────────────────────────────────────────────────────────────

    // ── Real-time broadcast via Socket.IO ────────────────────────────────
    try {
      getIo()?.emit('new_detection', {
        url: url.trim(),
        prediction: mlResult.prediction,
        riskLevel: mlResult.risk_level,
        confidence: mlResult.confidence,
        campaignId,
        timestamp: new Date().toISOString(),
      });
    } catch (socketErr) {
      console.error('[SOCKET] Emit error (non-fatal):', socketErr.message);
    }
    // ─────────────────────────────────────────────────────────────────────

    // ── AuditLog for high-risk behavioral actors ──────────────────────────
    if (behaviorResult.threatActorLikelihood >= 70) {
      try {
        await AuditLog.create({
          action: 'HIGH_RISK_BEHAVIORAL_ANOMALY',
          userId: req.user.id,
          details: {
            url: url.trim(),
            scanVelocity: behaviorResult.scanVelocity,
            threatActorLikelihood: behaviorResult.threatActorLikelihood,
          },
          ipAddress: req.ip,
          fingerprint,
          severity: 'Warning',
        });
        console.log(`[AUDIT] High-risk actor flagged — likelihood: ${behaviorResult.threatActorLikelihood}%`);
      } catch (auditErr) {
        console.error('[AUDIT] Log error (non-fatal):', auditErr.message);
      }
    }
    // ─────────────────────────────────────────────────────────────────────

    // (scan count increment removed — unlimited scans)

    // ── AUTO-PROMOTE to Blacklist ───────────────────────────────────────────
    // Only auto-blacklist when fusion verdict is BLOCK (high-confidence phishing).
    // WARN verdicts are borderline — auto-blacklisting on WARN caused legitimate
    // sites (e.g. established news portals) to be permanently blocked.
    let autoBlacklisted = false;
    const _fusionVerdict = mlResult.fusion_result?.verdict;
    if (['Phishing', 'Suspicious'].includes(mlResult.prediction) &&
        !mlResult.is_trusted &&
        _fusionVerdict === 'BLOCK') {
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

    const remainingScans = 9999; // unlimited scans

    // Return result
    const responsePayload = {
      success: true,
      message: "URL analyzed successfully",
      cached: false,
      data: {
        ...mlResult,
        scanId: scanHistory._id,
        risk_emoji: getRiskEmoji(mlResult.risk_level),
        auto_blacklisted: autoBlacklisted,
        // campaign_info: Phase B result (URL added to campaign database).
        // Only present when prediction=Phishing and Phase B ran successfully.
        // Distinct from campaign_match (Phase A verdict override).
        campaign_info: campaignInfo,
      },
      userInfo: {
        isPremium: user.isPremium,
        remainingScans,
        totalScans: user.totalScans
      }
    };

    // Resolve any waiting duplicate requests, then clean up
    _resolveInFlight?.(responsePayload);
    _inFlightScans.delete(_dedupKey);

    res.status(200).json(responsePayload);

  } catch (error) {
    // Clean up in-flight entry so future scans for this URL aren't stuck waiting
    if (typeof _resolveInFlight === 'function') _resolveInFlight(null);
    if (typeof _dedupKey === 'string') _inFlightScans.delete(_dedupKey);
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

    const scan = await ScanHistory.findOneAndDelete({ _id: scanId, userId });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found"
      });
    }

    // Also remove from Blacklist — deleting a scan means the user considers
    // it a false positive and doesn't want the domain blocked in future scans.
    if (scan.url) {
      try {
        const normalizedDomain = Blacklist.normalizeDomain(scan.url);
        const removed = await Blacklist.findOneAndDelete({ normalizedDomain });
        if (removed) {
          console.log(`[BLACKLIST] Removed on scan delete: ${normalizedDomain}`);
        }
      } catch (blErr) {
        console.error('[BLACKLIST] Cleanup on scan delete failed:', blErr.message);
        // Non-fatal — scan already deleted, continue
      }
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

    await entry.deleteOne();
    console.log(`[BLACKLIST] Deleted (false positive): ${normalizedDomain} by user ${req.user.id}`);

    // Also delete all ScanHistory entries for this domain so they don't
    // show up in history and re-trigger auto-blacklisting on the next scan.
    const deleted = await ScanHistory.deleteMany({ domain: normalizedDomain });
    if (deleted.deletedCount > 0) {
      console.log(`[SCANHISTORY] Removed ${deleted.deletedCount} entries for ${normalizedDomain}`);
    }

    res.status(200).json({
      success: true,
      message: `${normalizedDomain} removed from blacklist and scan history.`
    });

  } catch (error) {
    console.error('Remove from blacklist error:', error);
    next(error);
  }
};

// ==================== DELETE CAMPAIGN (false positive) ====================
export const deleteCampaign = async (req, res, next) => {
  try {
    const { campaignId } = req.params;
    const campaign = await Campaign.findById(campaignId);
    if (!campaign) {
      return res.status(404).json({ success: false, message: 'Campaign not found' });
    }
    await campaign.deleteOne();
    console.log(`[CAMPAIGN] Deleted (false positive): ${campaignId} by user ${req.user.id}`);
    res.status(200).json({ success: true, message: `Campaign ${campaign.name} deleted.` });
  } catch (error) {
    console.error('Delete campaign error:', error);
    next(error);
  }
};

// ==================== GET CAMPAIGNS ====================
export const getCampaigns = async (_req, res, next) => {
  try {
    const campaigns = await Campaign.find({ status: 'Active' })
      .sort({ lastSeen: -1 })
      .limit(20)
      .select('name totalHits threatLevel firstSeen lastSeen detectedUrls');

    res.status(200).json({ success: true, campaigns });
  } catch (error) {
    console.error('Get campaigns error:', error);
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
