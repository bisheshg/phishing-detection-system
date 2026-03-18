"""
PhishNet Accuracy Benchmark
============================
Fetches real phishing URLs from public threat intelligence feeds and
real legitimate URLs from the Tranco top-1M list, then runs every URL
through the PhishNet Flask service and computes detection metrics.

Sources
-------
  Phishing  : PhishTank community feed (CSV, free)
              OpenPhish community feed (plain-text, free)
              URLhaus (abuse.ch REST API, free)
  Legitimate: Tranco top-1M list (random sample, free)
              Curated always-up baseline list

Metrics
-------
  Accuracy · Precision · Recall (TPR) · F1 · FPR · AUC-ROC
  Per-source breakdown · Confusion matrix

Output
------
  reports/benchmark_YYYYMMDD_HHMMSS.json   — full per-URL detail
  reports/benchmark_YYYYMMDD_HHMMSS.csv    — one row per URL
  reports/benchmark_YYYYMMDD_HHMMSS.png    — charts (if matplotlib available)
  Console summary table

Usage
-----
  # Quick run: 50 phishing + 50 legit
  python benchmark_accuracy.py

  # Full run: 200 phishing + 200 legit, higher concurrency
  python benchmark_accuracy.py --phishing 200 --legit 200 --workers 8

  # Include Google Safe Browsing verification (needs API key)
  python benchmark_accuracy.py --gsb-key YOUR_KEY

  # Skip slow sources (URLhaus only)
  python benchmark_accuracy.py --sources urlhaus --phishing 100

  # Use specific sources
  python benchmark_accuracy.py --sources phishtank openphish --phishing 100 --legit 100

  # Save results to custom directory
  python benchmark_accuracy.py --report-dir my_reports
"""

import argparse
import csv
import gzip
import io
import json
import logging
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

# ── Optional imports ───────────────────────────────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix, roc_curve,
    )
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("[warn] scikit-learn not installed — AUC-ROC will be skipped")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[warn] matplotlib not installed — charts will be skipped")

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("benchmark")


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    url: str
    true_label: int          # 1 = phishing, 0 = legitimate
    source: str              # phishtank / openphish / urlhaus / tranco / baseline

    # Filled after scan
    predicted_label: int = -1   # 1 = phishing/suspicious, 0 = legitimate
    predicted_prob:  float = 0.0
    prediction_text: str = ""   # Phishing / Suspicious / Legitimate
    fusion_verdict:  str = ""   # BLOCK / WARN / ALLOW
    scenario:        str = ""
    latency_ms:      float = 0.0
    error:           str = ""
    skipped:         bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# URL FETCHERS — Threat Intel Feeds
# ═══════════════════════════════════════════════════════════════════════════════

_HEADERS = {
    "User-Agent": "PhishNet-Benchmark/1.0 (academic research; contact: research@phishnet.local)"
}

def fetch_phishtank(limit: int) -> List[Tuple[str, str]]:
    """
    Fetch verified active phishing URLs from PhishTank community feed.
    Returns list of (url, 'phishtank') tuples.

    PhishTank publishes a free CSV at data.phishtank.com — no API key needed
    for the community data file (they ask for a User-Agent header).
    """
    log.info("PhishTank: fetching community feed CSV…")
    # PhishTank community feed — gzipped CSV of all currently verified phishing URLs
    feed_url = "http://data.phishtank.com/data/online-valid.csv.gz"
    try:
        resp = requests.get(feed_url, headers=_HEADERS, timeout=30, stream=True)
        resp.raise_for_status()
        raw = gzip.decompress(resp.content)
        lines = raw.decode("utf-8", errors="replace").splitlines()
        # CSV header: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
        reader = csv.DictReader(lines)
        urls = []
        for row in reader:
            u = row.get("url", "").strip()
            if u and u.startswith("http") and len(u) < 2000:
                urls.append((u, "phishtank"))
        random.shuffle(urls)
        log.info(f"PhishTank: {len(urls)} total → sampling {min(limit, len(urls))}")
        return urls[:limit]
    except Exception as e:
        log.warning(f"PhishTank feed failed ({e}) — trying JSON fallback")
        return _phishtank_json_fallback(limit)


def _phishtank_json_fallback(limit: int) -> List[Tuple[str, str]]:
    """Fallback: PhishTank JSON feed (larger download but same data)."""
    feed_url = "http://data.phishtank.com/data/online-valid.json.gz"
    try:
        resp = requests.get(feed_url, headers=_HEADERS, timeout=45, stream=True)
        resp.raise_for_status()
        data = json.loads(gzip.decompress(resp.content))
        urls = [(e["url"], "phishtank") for e in data if e.get("url", "").startswith("http")]
        random.shuffle(urls)
        log.info(f"PhishTank JSON fallback: {len(urls)} → sampling {min(limit, len(urls))}")
        return urls[:limit]
    except Exception as e:
        log.error(f"PhishTank JSON fallback also failed: {e}")
        return []


def fetch_openphish(limit: int) -> List[Tuple[str, str]]:
    """
    Fetch from OpenPhish community feed.
    Free plain-text feed at openphish.com/feed.txt — one URL per line.
    Updated every 12 hours.
    """
    log.info("OpenPhish: fetching community feed…")
    feed_url = "https://openphish.com/feed.txt"
    try:
        resp = requests.get(feed_url, headers=_HEADERS, timeout=20)
        resp.raise_for_status()
        urls = [
            (line.strip(), "openphish")
            for line in resp.text.splitlines()
            if line.strip().startswith("http")
        ]
        random.shuffle(urls)
        log.info(f"OpenPhish: {len(urls)} total → sampling {min(limit, len(urls))}")
        return urls[:limit]
    except Exception as e:
        log.warning(f"OpenPhish feed failed: {e}")
        return []


def fetch_urlhaus(limit: int) -> List[Tuple[str, str]]:
    """
    Fetch recent malicious URLs from URLhaus (abuse.ch).
    REST API — no key needed, returns JSON with most recent 1000 URLs.
    Filters for URLs that are still online and tagged phishing/malware.
    """
    log.info("URLhaus: fetching recent URLs from abuse.ch…")
    api_url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    try:
        resp = requests.post(api_url, data={"limit": 1000}, headers=_HEADERS, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        urls = []
        for entry in data.get("urls", []):
            u = entry.get("url", "")
            status = entry.get("url_status", "")
            tags = [t.lower() for t in (entry.get("tags") or [])]
            # Only include online phishing/scam entries
            if u.startswith("http") and status == "online":
                urls.append((u, "urlhaus"))
        random.shuffle(urls)
        log.info(f"URLhaus: {len(urls)} online URLs → sampling {min(limit, len(urls))}")
        return urls[:limit]
    except Exception as e:
        log.warning(f"URLhaus feed failed: {e}")
        return []


def fetch_tranco(limit: int) -> List[Tuple[str, str]]:
    """
    Fetch top legitimate domains from the Tranco list (tranco-list.eu).
    Tranco aggregates Alexa, Majestic, Umbrella, Quantcast and removes
    known malicious domains — the gold standard for legitimate site lists.

    Uses a representative subset of ranks 50–10000 (avoids hyper-CDN top-50
    that are often blocked by corporate firewalls during testing).
    """
    log.info("Tranco: fetching top-1M list…")
    # Direct download of the latest Tranco 1M list (CSV: rank,domain)
    list_url = "https://tranco-list.eu/download/recent/1M"
    try:
        resp = requests.get(list_url, headers=_HEADERS, timeout=30, stream=True)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        # Sample from ranks 100–50000 to avoid hyper-CDN domains at the very top
        # and obscure domains at the bottom that may be parked/expired
        domains = []
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) == 2:
                rank, domain = parts
                try:
                    rank_int = int(rank)
                    if 100 <= rank_int <= 50000:
                        domains.append(domain.strip())
                except ValueError:
                    continue
        random.shuffle(domains)
        sample = domains[:limit]
        urls = [(f"https://{d}", "tranco") for d in sample]
        log.info(f"Tranco: {len(domains)} eligible → sampling {len(urls)}")
        return urls
    except Exception as e:
        log.warning(f"Tranco list failed: {e}")
        return []


def fetch_gsb_verification(urls: List[str], api_key: str) -> Dict[str, bool]:
    """
    Optional: verify URL labels against Google Safe Browsing API v4.
    Returns dict: url → True if GSB confirms phishing/malware, False otherwise.
    Requires a free Google Cloud API key with Safe Browsing API enabled.
    """
    log.info(f"Google Safe Browsing: verifying {len(urls)} URLs…")
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    results = {}
    # GSB allows max 500 URLs per request
    batch_size = 500
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i + batch_size]
        payload = {
            "client": {"clientId": "phishnet-benchmark", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "PHISHING"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": u} for u in batch],
            },
        }
        try:
            resp = requests.post(gsb_url, json=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for match in data.get("matches", []):
                results[match["threat"]["url"]] = True
            # URLs not in results are clean
            for u in batch:
                if u not in results:
                    results[u] = False
        except Exception as e:
            log.warning(f"GSB batch {i//batch_size + 1} failed: {e}")
    return results


# Curated baseline legit URLs — always available even if Tranco fails
_BASELINE_LEGIT = [
    ("https://www.google.com",       "baseline"),
    ("https://www.wikipedia.org",    "baseline"),
    ("https://www.github.com",       "baseline"),
    ("https://www.stackoverflow.com","baseline"),
    ("https://www.bbc.com",          "baseline"),
    ("https://www.reddit.com",       "baseline"),
    ("https://www.mozilla.org",      "baseline"),
    ("https://www.python.org",       "baseline"),
    ("https://www.cloudflare.com",   "baseline"),
    ("https://www.apple.com",        "baseline"),
    ("https://www.microsoft.com",    "baseline"),
    ("https://www.amazon.com",       "baseline"),
    ("https://www.youtube.com",      "baseline"),
    ("https://www.linkedin.com",     "baseline"),
    ("https://www.netflix.com",      "baseline"),
    ("https://www.paypal.com",       "baseline"),
    ("https://www.twitter.com",      "baseline"),
    ("https://www.instagram.com",    "baseline"),
    ("https://www.adobe.com",        "baseline"),
    ("https://www.dropbox.com",      "baseline"),
    ("https://www.zoom.us",          "baseline"),
    ("https://www.slack.com",        "baseline"),
    ("https://www.shopify.com",      "baseline"),
    ("https://www.stripe.com",       "baseline"),
    ("https://www.atlassian.com",    "baseline"),
    ("https://www.godaddy.com",      "baseline"),
    ("https://www.namecheap.com",    "baseline"),
    ("https://scholar.google.com",   "baseline"),
    ("https://www.nytimes.com",      "baseline"),
    ("https://www.cnn.com",          "baseline"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER — Calls PhishNet Flask /analyze_url
# ═══════════════════════════════════════════════════════════════════════════════

def scan_url(result: ScanResult, flask_url: str, timeout: int) -> ScanResult:
    """Send URL to Flask /analyze_url and populate result fields."""
    t0 = time.perf_counter()
    try:
        resp = requests.post(
            f"{flask_url}/analyze_url",
            json={"url": result.url},
            timeout=timeout,
        )
        result.latency_ms = (time.perf_counter() - t0) * 1000
        if resp.status_code != 200:
            result.error = f"HTTP {resp.status_code}"
            result.skipped = True
            return result

        data = resp.json()

        # Extract core verdict fields
        result.prediction_text = data.get("prediction", "")
        result.predicted_prob  = float(data.get("probability", 0.5))
        result.fusion_verdict  = data.get("fusion_result", {}).get("verdict", "")
        result.scenario        = data.get("fusion_result", {}).get("scenario", "")

        # Map to binary label:
        # Phishing or Suspicious → 1  (predicted positive)
        # Legitimate → 0              (predicted negative)
        pred = result.prediction_text.lower()
        if pred in ("phishing", "suspicious"):
            result.predicted_label = 1
        elif pred == "legitimate":
            result.predicted_label = 0
        else:
            result.error = f"unknown prediction: {result.prediction_text}"
            result.skipped = True

    except requests.Timeout:
        result.latency_ms = (time.perf_counter() - t0) * 1000
        result.error = "timeout"
        result.skipped = True
    except Exception as e:
        result.latency_ms = (time.perf_counter() - t0) * 1000
        result.error = str(e)[:120]
        result.skipped = True

    return result


def scan_all(
    items: List[ScanResult],
    flask_url: str,
    workers: int,
    timeout: int,
    desc: str = "Scanning",
) -> List[ScanResult]:
    """Run scan_url concurrently for all items."""
    results = []
    iterator = items
    if HAS_TQDM:
        iterator = tqdm(items, desc=desc, unit="url", ncols=80)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_url, r, flask_url, timeout): r for r in items}
        completed = 0
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            completed += 1
            if HAS_TQDM:
                iterator.update(1)  # type: ignore[union-attr]
            elif completed % 10 == 0:
                log.info(f"  {completed}/{len(items)} scanned…")

    if HAS_TQDM:
        iterator.close()  # type: ignore[union-attr]
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════════════════════════

def compute_metrics(results: List[ScanResult]) -> dict:
    """Compute overall and per-source detection metrics."""
    valid = [r for r in results if not r.skipped and r.predicted_label >= 0]
    if not valid:
        return {}

    y_true  = [r.true_label      for r in valid]
    y_pred  = [r.predicted_label for r in valid]
    y_prob  = [r.predicted_prob  for r in valid]
    latencies = [r.latency_ms    for r in valid]

    if not HAS_SKLEARN:
        # Manual metric computation
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0)
        accuracy  = (tp + tn) / len(y_true) if y_true else 0
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0
        cm = [[tn, fp], [fn, tp]]
        auc = None
    else:
        tp = int(sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1))
        fp = int(sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1))
        tn = int(sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0))
        fn = int(sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0))
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall    = float(recall_score(y_true, y_pred, zero_division=0))
        f1        = float(f1_score(y_true, y_pred, zero_division=0))
        accuracy  = float(accuracy_score(y_true, y_pred))
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        try:
            auc = float(roc_auc_score(y_true, y_prob))
        except Exception:
            auc = None

    # Per-source breakdown
    sources = list({r.source for r in valid})
    per_source = {}
    for src in sorted(sources):
        src_results = [r for r in valid if r.source == src]
        s_true = [r.true_label      for r in src_results]
        s_pred = [r.predicted_label for r in src_results]
        s_tp = sum(1 for t, p in zip(s_true, s_pred) if t == 1 and p == 1)
        s_fp = sum(1 for t, p in zip(s_true, s_pred) if t == 0 and p == 1)
        s_tn = sum(1 for t, p in zip(s_true, s_pred) if t == 0 and p == 0)
        s_fn = sum(1 for t, p in zip(s_true, s_pred) if t == 1 and p == 0)
        s_prec = s_tp / (s_tp + s_fp) if (s_tp + s_fp) > 0 else 0
        s_rec  = s_tp / (s_tp + s_fn) if (s_tp + s_fn) > 0 else 0
        s_f1   = (2 * s_prec * s_rec / (s_prec + s_rec) if (s_prec + s_rec) > 0 else 0)
        s_acc  = (s_tp + s_tn) / len(s_true) if s_true else 0
        per_source[src] = {
            "total": len(src_results),
            "tp": s_tp, "fp": s_fp, "tn": s_tn, "fn": s_fn,
            "precision": round(s_prec, 4),
            "recall":    round(s_rec,  4),
            "f1":        round(s_f1,   4),
            "accuracy":  round(s_acc,  4),
        }

    # Scenario distribution (what fusion paths were hit)
    scenario_counts: Dict[str, int] = {}
    for r in valid:
        scenario_counts[r.scenario or "unknown"] = scenario_counts.get(r.scenario or "unknown", 0) + 1

    # Latency stats
    lat_sorted = sorted(latencies)
    n = len(lat_sorted)

    skipped = [r for r in results if r.skipped]
    skip_reasons: Dict[str, int] = {}
    for r in skipped:
        skip_reasons[r.error or "unknown"] = skip_reasons.get(r.error or "unknown", 0) + 1

    return {
        "total_scanned": len(results),
        "total_valid":   len(valid),
        "total_skipped": len(skipped),
        "skip_reasons":  skip_reasons,
        "confusion_matrix": {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        },
        "accuracy":  round(accuracy,  4),
        "precision": round(precision, 4),
        "recall":    round(recall,    4),  # = TPR (sensitivity)
        "f1":        round(f1,        4),
        "fpr":       round(fpr,       4),  # False Positive Rate (1-specificity)
        "specificity": round(1 - fpr, 4),
        "auc_roc":   round(auc, 4) if auc is not None else None,
        "latency_ms": {
            "avg":    round(sum(latencies) / n, 1),
            "median": round(lat_sorted[n // 2], 1),
            "p95":    round(lat_sorted[int(n * 0.95)], 1),
            "p99":    round(lat_sorted[int(n * 0.99)], 1),
            "min":    round(lat_sorted[0], 1),
            "max":    round(lat_sorted[-1], 1),
        },
        "per_source":       per_source,
        "scenario_distribution": dict(sorted(scenario_counts.items(),
                                             key=lambda x: -x[1])),
        # For ROC curve
        "y_true": y_true,
        "y_prob": y_prob,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(metrics: dict, args: argparse.Namespace):
    """Print formatted benchmark summary to console."""
    if not metrics:
        print("\n[!] No valid results to report.\n")
        return

    cm = metrics["confusion_matrix"]
    lat = metrics["latency_ms"]

    print("\n" + "═" * 68)
    print("  PhishNet Accuracy Benchmark — Results")
    print("═" * 68)
    print(f"\n  {'Total URLs scanned':<30} {metrics['total_scanned']:>6}")
    print(f"  {'Valid results':<30} {metrics['total_valid']:>6}")
    print(f"  {'Skipped (timeout/error)':<30} {metrics['total_skipped']:>6}")

    print(f"\n  {'─'*40}")
    print(f"  {'DETECTION METRICS':^40}")
    print(f"  {'─'*40}")
    print(f"  {'Accuracy':<30} {metrics['accuracy']*100:>6.2f}%")
    print(f"  {'Precision':<30} {metrics['precision']*100:>6.2f}%")
    print(f"  {'Recall (TPR)':<30} {metrics['recall']*100:>6.2f}%")
    print(f"  {'F1 Score':<30} {metrics['f1']*100:>6.2f}%")
    print(f"  {'False Positive Rate':<30} {metrics['fpr']*100:>6.2f}%")
    print(f"  {'Specificity (TNR)':<30} {metrics['specificity']*100:>6.2f}%")
    if metrics.get("auc_roc") is not None:
        print(f"  {'AUC-ROC':<30} {metrics['auc_roc']:>6.4f}")

    print(f"\n  {'─'*40}")
    print(f"  {'CONFUSION MATRIX':^40}")
    print(f"  {'─'*40}")
    print(f"  {'':>18} Predicted+   Predicted-")
    print(f"  {'Actual Phishing':<18} TP={cm['TP']:<7}   FN={cm['FN']}")
    print(f"  {'Actual Legit':<18} FP={cm['FP']:<7}   TN={cm['TN']}")

    print(f"\n  {'─'*40}")
    print(f"  {'LATENCY':^40}")
    print(f"  {'─'*40}")
    print(f"  {'Avg':<30} {lat['avg']:>6.0f} ms")
    print(f"  {'Median':<30} {lat['median']:>6.0f} ms")
    print(f"  {'P95':<30} {lat['p95']:>6.0f} ms")
    print(f"  {'P99':<30} {lat['p99']:>6.0f} ms")

    if metrics.get("per_source"):
        print(f"\n  {'─'*66}")
        print(f"  {'PER-SOURCE BREAKDOWN':^66}")
        print(f"  {'─'*66}")
        hdr = f"  {'Source':<15} {'Total':>6}  {'TP':>5}  {'FP':>5}  {'FN':>5}  {'TN':>5}  {'Recall':>8}  {'FPR':>6}  {'F1':>6}"
        print(hdr)
        print("  " + "─" * 64)
        for src, s in metrics["per_source"].items():
            fpr_src = s["fp"] / (s["fp"] + s["tn"]) if (s["fp"] + s["tn"]) > 0 else 0
            print(f"  {src:<15} {s['total']:>6}  {s['tp']:>5}  {s['fp']:>5}  "
                  f"{s['fn']:>5}  {s['tn']:>5}  "
                  f"{s['recall']*100:>7.1f}%  {fpr_src*100:>5.1f}%  {s['f1']*100:>5.1f}%")

    if metrics.get("scenario_distribution"):
        print(f"\n  {'─'*40}")
        print(f"  {'FUSION SCENARIO DISTRIBUTION':^40}")
        print(f"  {'─'*40}")
        total_v = metrics["total_valid"]
        for scenario, count in list(metrics["scenario_distribution"].items())[:10]:
            bar = "█" * int(count / total_v * 30)
            print(f"  {scenario:<35} {count:>4} ({count/total_v*100:5.1f}%) {bar}")

    print("\n" + "═" * 68 + "\n")


def save_reports(results: List[ScanResult], metrics: dict, report_dir: str) -> str:
    """Save JSON + CSV reports. Returns base filename."""
    os.makedirs(report_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(report_dir, f"benchmark_{ts}")

    # Strip y_true/y_prob arrays from saved JSON (too large, reconstruction possible from CSV)
    save_metrics = {k: v for k, v in metrics.items() if k not in ("y_true", "y_prob")}

    # JSON
    report_data = {
        "timestamp":  datetime.now().isoformat(),
        "metrics":    save_metrics,
        "results": [
            {
                "url":              r.url,
                "true_label":       r.true_label,
                "source":           r.source,
                "predicted_label":  r.predicted_label,
                "predicted_prob":   round(r.predicted_prob, 4),
                "prediction_text":  r.prediction_text,
                "fusion_verdict":   r.fusion_verdict,
                "scenario":         r.scenario,
                "latency_ms":       round(r.latency_ms, 1),
                "error":            r.error,
                "skipped":          r.skipped,
            }
            for r in results
        ],
    }
    json_path = base + ".json"
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)
    log.info(f"JSON report → {json_path}")

    # CSV
    csv_path = base + ".csv"
    fieldnames = [
        "url", "true_label", "source", "predicted_label", "predicted_prob",
        "prediction_text", "fusion_verdict", "scenario", "latency_ms", "error", "skipped",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "url":             r.url[:512],
                "true_label":      r.true_label,
                "source":          r.source,
                "predicted_label": r.predicted_label,
                "predicted_prob":  round(r.predicted_prob, 4),
                "prediction_text": r.prediction_text,
                "fusion_verdict":  r.fusion_verdict,
                "scenario":        r.scenario,
                "latency_ms":      round(r.latency_ms, 1),
                "error":           r.error,
                "skipped":         r.skipped,
            })
    log.info(f"CSV report → {csv_path}")

    return base


def save_charts(metrics: dict, base_path: str):
    """Generate benchmark charts and save as PNG."""
    if not HAS_MPL:
        return
    if not metrics:
        return

    fig = plt.figure(figsize=(18, 12))
    fig.suptitle("PhishNet Accuracy Benchmark", fontsize=16, fontweight="bold", y=0.98)
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

    # ── 1. Metric bar chart ──────────────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, 0])
    metric_names  = ["Accuracy", "Precision", "Recall\n(TPR)", "F1", "Specificity\n(TNR)"]
    metric_vals   = [
        metrics["accuracy"], metrics["precision"], metrics["recall"],
        metrics["f1"], metrics["specificity"],
    ]
    colors = ["#2196F3", "#4CAF50", "#FF9800", "#9C27B0", "#00BCD4"]
    bars = ax1.bar(metric_names, [v * 100 for v in metric_vals], color=colors, edgecolor="white", linewidth=0.8)
    for bar, val in zip(bars, metric_vals):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 f"{val*100:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax1.set_ylim(0, 115)
    ax1.set_ylabel("Score (%)")
    ax1.set_title("Overall Detection Metrics")
    ax1.axhline(y=90, color="red", linestyle="--", alpha=0.4, linewidth=1, label="90% target")
    ax1.legend(fontsize=8)
    ax1.grid(axis="y", alpha=0.3)

    # ── 2. Confusion matrix heatmap ──────────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    cm = metrics["confusion_matrix"]
    cm_array = np.array([[cm["TN"], cm["FP"]], [cm["FN"], cm["TP"]]])
    im = ax2.imshow(cm_array, interpolation="nearest", cmap="Blues")
    ax2.set_xticks([0, 1])
    ax2.set_yticks([0, 1])
    ax2.set_xticklabels(["Predicted Legit", "Predicted Phishing"])
    ax2.set_yticklabels(["Actual Legit", "Actual Phishing"])
    plt.setp(ax2.get_xticklabels(), rotation=20, ha="right", fontsize=8)
    for i in range(2):
        for j in range(2):
            val = cm_array[i, j]
            color = "white" if val > cm_array.max() * 0.5 else "black"
            ax2.text(j, i, str(val), ha="center", va="center",
                     fontsize=14, fontweight="bold", color=color)
    ax2.set_title("Confusion Matrix")

    # ── 3. ROC curve ─────────────────────────────────────────────────────────
    ax3 = fig.add_subplot(gs[0, 2])
    y_true_roc = metrics.get("y_true")
    y_prob_roc = metrics.get("y_prob")
    if HAS_SKLEARN and y_true_roc and y_prob_roc and len(set(y_true_roc)) > 1:
        fpr_roc, tpr_roc, _ = roc_curve(y_true_roc, y_prob_roc)
        auc_val = metrics.get("auc_roc", 0)
        ax3.plot(fpr_roc, tpr_roc, color="#2196F3", lw=2, label=f"AUC = {auc_val:.3f}")
        ax3.fill_between(fpr_roc, tpr_roc, alpha=0.15, color="#2196F3")
        ax3.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Random")
        ax3.set_xlabel("False Positive Rate")
        ax3.set_ylabel("True Positive Rate")
        ax3.set_title("ROC Curve")
        ax3.legend(fontsize=9)
        ax3.grid(alpha=0.3)
    else:
        ax3.text(0.5, 0.5, "ROC not available\n(single class or\nmissing sklearn)",
                 ha="center", va="center", fontsize=10, transform=ax3.transAxes)
        ax3.set_title("ROC Curve")

    # ── 4. Per-source recall + FPR ───────────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 0])
    src_names = list(metrics.get("per_source", {}).keys())
    if src_names:
        src_recall = [metrics["per_source"][s]["recall"] * 100 for s in src_names]
        src_fpr    = [
            (metrics["per_source"][s]["fp"] /
             (metrics["per_source"][s]["fp"] + metrics["per_source"][s]["tn"]) * 100
             if (metrics["per_source"][s]["fp"] + metrics["per_source"][s]["tn"]) > 0 else 0)
            for s in src_names
        ]
        x = np.arange(len(src_names))
        w = 0.35
        ax4.bar(x - w/2, src_recall, w, label="Recall (TPR)", color="#4CAF50", alpha=0.85)
        ax4.bar(x + w/2, src_fpr,    w, label="FPR",          color="#F44336", alpha=0.85)
        ax4.set_xticks(x)
        ax4.set_xticklabels(src_names, rotation=20, ha="right", fontsize=8)
        ax4.set_ylabel("Rate (%)")
        ax4.set_title("Per-Source Recall vs FPR")
        ax4.legend(fontsize=8)
        ax4.grid(axis="y", alpha=0.3)
        ax4.set_ylim(0, 115)

    # ── 5. Fusion scenario distribution ─────────────────────────────────────
    ax5 = fig.add_subplot(gs[1, 1])
    scenario_dist = metrics.get("scenario_distribution", {})
    if scenario_dist:
        top_n = 8
        sc_items = list(scenario_dist.items())[:top_n]
        sc_names = [s[0].replace("_", "\n") for s in sc_items]
        sc_vals  = [s[1] for s in sc_items]
        cmap = plt.cm.tab10
        colors_sc = [cmap(i / len(sc_items)) for i in range(len(sc_items))]
        ax5.barh(sc_names[::-1], sc_vals[::-1], color=colors_sc[::-1], alpha=0.85, edgecolor="white")
        ax5.set_xlabel("Count")
        ax5.set_title("Fusion Scenario Distribution")
        ax5.grid(axis="x", alpha=0.3)

    # ── 6. Latency distribution ──────────────────────────────────────────────
    ax6 = fig.add_subplot(gs[1, 2])
    lat = metrics.get("latency_ms", {})
    if lat:
        lat_items = ["Min", "Median", "Avg", "P95", "P99"]
        lat_vals  = [lat["min"], lat["median"], lat["avg"], lat["p95"], lat["p99"]]
        lat_colors = ["#4CAF50", "#2196F3", "#FF9800", "#FF5722", "#F44336"]
        bars6 = ax6.bar(lat_items, lat_vals, color=lat_colors, alpha=0.85, edgecolor="white")
        for bar, val in zip(bars6, lat_vals):
            ax6.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 20,
                     f"{val:.0f}ms", ha="center", va="bottom", fontsize=9)
        ax6.set_ylabel("ms")
        ax6.set_title("Latency Profile")
        ax6.grid(axis="y", alpha=0.3)

    # Watermark
    fig.text(0.99, 0.01, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
             ha="right", fontsize=7, color="gray")

    png_path = base_path + ".png"
    plt.savefig(png_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    log.info(f"Charts → {png_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="PhishNet Accuracy Benchmark — fetch real phishing/legit URLs and measure detection metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--flask-url",   default="http://localhost:5002",
                   help="Flask ML service base URL (default: http://localhost:5002)")
    p.add_argument("--phishing",    type=int, default=50,
                   help="Number of phishing URLs to test (default: 50)")
    p.add_argument("--legit",       type=int, default=50,
                   help="Number of legitimate URLs to test (default: 50)")
    p.add_argument("--workers",     type=int, default=4,
                   help="Concurrent scan workers (default: 4)")
    p.add_argument("--timeout",     type=int, default=30,
                   help="Per-URL scan timeout in seconds (default: 30)")
    p.add_argument("--sources",     nargs="+",
                   choices=["phishtank", "openphish", "urlhaus", "tranco", "all"],
                   default=["all"],
                   help="Which sources to use (default: all)")
    p.add_argument("--report-dir",  default="reports",
                   help="Directory to save reports (default: reports/)")
    p.add_argument("--gsb-key",     default=None,
                   help="Google Safe Browsing API key (optional — enables GSB verification)")
    p.add_argument("--seed",        type=int, default=42,
                   help="Random seed for reproducible sampling (default: 42)")
    p.add_argument("--no-charts",   action="store_true",
                   help="Skip chart generation even if matplotlib is available")
    p.add_argument("--suspicious-as-phishing", action="store_true", default=True,
                   help="Count 'Suspicious' predictions as phishing detections (default: True)")
    return p.parse_args()


def main():
    args = parse_args()
    random.seed(args.seed)

    use_all     = "all" in args.sources
    use_pt      = use_all or "phishtank"  in args.sources
    use_op      = use_all or "openphish"  in args.sources
    use_uh      = use_all or "urlhaus"    in args.sources
    use_tranco  = use_all or "tranco"     in args.sources

    print("\n" + "═" * 68)
    print("  PhishNet Accuracy Benchmark")
    print(f"  Flask URL  : {args.flask_url}")
    print(f"  Phishing   : {args.phishing} URLs from " +
          ", ".join(filter(None, [
              "PhishTank" if use_pt else "",
              "OpenPhish"  if use_op else "",
              "URLhaus"    if use_uh else "",
          ])))
    print(f"  Legitimate : {args.legit} URLs from " +
          ", ".join(filter(None, [
              "Tranco" if use_tranco else "",
              "Baseline curated list",
          ])))
    print(f"  Workers    : {args.workers}   Timeout: {args.timeout}s")
    print("═" * 68 + "\n")

    # ── Health check ──────────────────────────────────────────────────────────
    try:
        r = requests.get(f"{args.flask_url}/health", timeout=5)
        log.info(f"Flask health check: OK ({r.status_code})")
    except Exception:
        try:
            r = requests.post(f"{args.flask_url}/analyze_url",
                              json={"url": "https://www.google.com"}, timeout=10)
            log.info("Flask reachable (health endpoint not present, /analyze_url responded)")
        except Exception as e:
            log.error(f"Flask service unreachable at {args.flask_url}: {e}")
            log.error("Start Flask with: cd FlaskBack && python app.py")
            sys.exit(1)

    # ── Fetch phishing URLs ───────────────────────────────────────────────────
    phishing_pool: List[Tuple[str, str]] = []

    if use_pt:
        per_source_limit = args.phishing // max(sum([use_pt, use_op, use_uh]), 1) + 20
        phishing_pool.extend(fetch_phishtank(per_source_limit))

    if use_op:
        per_source_limit = args.phishing // max(sum([use_pt, use_op, use_uh]), 1) + 20
        phishing_pool.extend(fetch_openphish(per_source_limit))

    if use_uh:
        per_source_limit = args.phishing // max(sum([use_pt, use_op, use_uh]), 1) + 20
        phishing_pool.extend(fetch_urlhaus(per_source_limit))

    # Deduplicate by URL
    seen_urls: set = set()
    deduped_phishing: List[Tuple[str, str]] = []
    for url, src in phishing_pool:
        if url not in seen_urls:
            seen_urls.add(url)
            deduped_phishing.append((url, src))

    random.shuffle(deduped_phishing)
    selected_phishing = deduped_phishing[:args.phishing]

    if not selected_phishing:
        log.error("No phishing URLs fetched from any source. Check network connectivity.")
        sys.exit(1)

    log.info(f"Phishing sample: {len(selected_phishing)} URLs (deduplicated from {len(phishing_pool)})")

    # ── Fetch legitimate URLs ─────────────────────────────────────────────────
    legit_pool: List[Tuple[str, str]] = list(_BASELINE_LEGIT)

    if use_tranco:
        tranco_urls = fetch_tranco(args.legit + 50)
        legit_pool.extend(tranco_urls)

    # Deduplicate
    seen_legit: set = set()
    deduped_legit: List[Tuple[str, str]] = []
    for url, src in legit_pool:
        if url not in seen_legit:
            seen_legit.add(url)
            deduped_legit.append((url, src))

    random.shuffle(deduped_legit)
    selected_legit = deduped_legit[:args.legit]
    log.info(f"Legitimate sample: {len(selected_legit)} URLs")

    # ── Optional GSB verification of phishing labels ──────────────────────────
    if args.gsb_key:
        phishing_urls_for_gsb = [u for u, _ in selected_phishing]
        gsb_results = fetch_gsb_verification(phishing_urls_for_gsb, args.gsb_key)
        # Filter to only GSB-confirmed phishing (strict labeling)
        selected_phishing = [
            (u, src) for u, src in selected_phishing
            if gsb_results.get(u, True)  # keep if GSB confirms OR if GSB missed it
        ]
        gsb_confirmed = sum(1 for v in gsb_results.values() if v)
        log.info(f"GSB verification: {gsb_confirmed}/{len(gsb_results)} confirmed by Google Safe Browsing")

    # ── Build ScanResult list ─────────────────────────────────────────────────
    all_scans: List[ScanResult] = []

    for url, src in selected_phishing:
        all_scans.append(ScanResult(url=url, true_label=1, source=src))

    for url, src in selected_legit:
        all_scans.append(ScanResult(url=url, true_label=0, source=src))

    random.shuffle(all_scans)  # Interleave phishing and legit

    log.info(f"\nStarting scan: {len(all_scans)} URLs ({args.workers} workers, {args.timeout}s timeout)\n")
    t_start = time.perf_counter()

    # ── Run scans ─────────────────────────────────────────────────────────────
    results = scan_all(
        all_scans,
        flask_url=args.flask_url,
        workers=args.workers,
        timeout=args.timeout,
        desc="Benchmarking",
    )

    elapsed = time.perf_counter() - t_start
    log.info(f"\nAll scans complete in {elapsed:.1f}s ({len(results)/elapsed:.1f} URLs/sec)")

    # ── Compute metrics ───────────────────────────────────────────────────────
    metrics = compute_metrics(results)

    # ── Print console summary ─────────────────────────────────────────────────
    print_summary(metrics, args)

    # ── Save reports ──────────────────────────────────────────────────────────
    base_path = save_reports(results, metrics, args.report_dir)

    if not args.no_charts:
        save_charts(metrics, base_path)

    print(f"  Reports saved to: {base_path}.*\n")


if __name__ == "__main__":
    main()
