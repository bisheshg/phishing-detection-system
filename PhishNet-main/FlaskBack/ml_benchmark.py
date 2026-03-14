"""
PhishNet ML Pipeline Micro-Benchmark
======================================
Measures execution time of each internal layer in the Flask ML pipeline.
Run directly against Flask at localhost:5002.

Usage:
    python ml_benchmark.py [--flask-url http://localhost:5002] [--runs 10]
"""

import time
import statistics
import json
import argparse
import requests
from dataclasses import dataclass, field
from typing import List, Dict

# ──────────────────────────────────────────────
# Test payloads targeting specific layers
# ──────────────────────────────────────────────

BENCHMARK_CASES = [
    {
        "name": "Short URL (bit.ly)",
        "url": "http://bit.ly/3xTest1",
        "expected_layers": ["url_expander", "url_normalizer", "rule_engine", "ml_ensemble"],
        "note": "Tests Layer 0a URL expansion overhead",
    },
    {
        "name": "IP Address URL",
        "url": "http://192.168.1.100/login.php",
        "expected_layers": ["url_normalizer", "rule_engine", "ml_ensemble"],
        "note": "IP flag + rule_engine CRITICAL hit. Skips cloaking.",
    },
    {
        "name": "Punycode Domain",
        "url": "http://xn--pple-43d.com/account/verify",
        "expected_layers": ["url_normalizer", "rule_engine", "ml_ensemble"],
        "note": "Tests homoglyph/punycode detection in normalizer",
    },
    {
        "name": "Trusted Domain (Google)",
        "url": "https://www.google.com",
        "expected_layers": ["url_normalizer", "rule_engine", "ml_ensemble", "shap"],
        "note": "Whitelist fast-path. Negative heuristic boost.",
    },
    {
        "name": "Long Suspicious URL",
        "url": "http://secure-paypal-account-update.verification.xyz/login?token=" + "x" * 150,
        "expected_layers": ["url_normalizer", "rule_engine", "feature_extraction", "ml_ensemble"],
        "note": "Tests URL_Length feature + rule engine cascade",
    },
    {
        "name": "HTTPS Legit Site",
        "url": "https://www.github.com/login",
        "expected_layers": ["feature_extraction", "ml_ensemble", "domain_metadata", "shap"],
        "note": "Full pipeline — WHOIS + SSL + ML + SHAP",
    },
    {
        "name": "Brand Lookalike",
        "url": "http://amazon-secure-login.com/verify",
        "expected_layers": ["rule_engine", "ml_ensemble", "visual_similarity", "fusion"],
        "note": "Triggers visual similarity analysis (brand keyword)",
    },
    {
        "name": "Many Subdomains",
        "url": "http://login.verify.secure.update.paypal.com.evil.xyz",
        "expected_layers": ["url_normalizer", "rule_engine", "ml_ensemble"],
        "note": "Tests subdomain enumeration + EXCESSIVE_SUBDOMAINS flag",
    },
]

@dataclass
class BenchmarkResult:
    name:        str
    url:         str
    note:        str
    runs:        int
    latencies:   List[float] = field(default_factory=list)
    errors:      int = 0
    layer_data:  Dict = field(default_factory=dict)  # from response if available

    @property
    def avg(self): return statistics.mean(self.latencies) if self.latencies else 0
    @property
    def p50(self): return statistics.median(self.latencies) if self.latencies else 0
    @property
    def p95(self):
        s = sorted(self.latencies)
        return s[int(len(s)*0.95)] if s else 0
    @property
    def stddev(self): return statistics.stdev(self.latencies) if len(self.latencies) > 1 else 0
    @property
    def min(self): return min(self.latencies) if self.latencies else 0
    @property
    def max(self): return max(self.latencies) if self.latencies else 0

def run_benchmark(flask_url: str, runs: int = 10):
    endpoint = f"{flask_url}/analyze"
    results  = []

    print("=" * 60)
    print("  PhishNet ML Pipeline Micro-Benchmark")
    print(f"  Flask: {flask_url}  |  Runs per case: {runs}")
    print("=" * 60)

    for case in BENCHMARK_CASES:
        print(f"\n  [{case['name']}]")
        print(f"  URL  : {case['url'][:65]}")
        print(f"  Note : {case['note']}")

        result = BenchmarkResult(
            name=case["name"], url=case["url"],
            note=case["note"], runs=runs,
        )

        # Warmup run (not counted)
        try:
            requests.post(endpoint, json={"url": case["url"]}, timeout=35)
        except Exception:
            pass

        for i in range(runs):
            t0 = time.perf_counter()
            try:
                resp = requests.post(endpoint, json={"url": case["url"]}, timeout=35)
                lat  = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    result.latencies.append(lat)
                    # Extract layer timing if available in response
                    data = resp.json()
                    if i == runs - 1:  # save last response metadata
                        result.layer_data = {
                            "prediction":  data.get("prediction"),
                            "confidence":  data.get("confidence"),
                            "risk_level":  data.get("risk_level"),
                            "base_prob":   data.get("base_probability"),
                            "risk_boost":  data.get("risk_boost"),
                            "rule_hits":   len(data.get("rule_analysis", {}).get("rule_violations", [])),
                            "shap_top":    data.get("shap_explanation", {}).get("top_features", [{}])[0].get("feature") if data.get("shap_explanation") else None,
                            "url_flags":   data.get("url_normalization", {}).get("flags", []),
                            "expanded_to": data.get("url_expansion", {}).get("final_url"),
                        }
                else:
                    result.errors += 1
            except Exception as e:
                result.errors += 1
                lat = (time.perf_counter() - t0) * 1000
                result.latencies.append(lat)

            dot = "." if result.latencies and result.latencies[-1] < 5000 else "!"
            print(f"  {dot}", end="", flush=True)

        print()  # newline after dots

        print(f"  Latency → avg={result.avg:.0f}ms  p50={result.p50:.0f}ms  "
              f"p95={result.p95:.0f}ms  stddev={result.stddev:.0f}ms  "
              f"min={result.min:.0f}ms  max={result.max:.0f}ms  errors={result.errors}")

        if result.layer_data:
            ld = result.layer_data
            print(f"  Result  → {ld.get('prediction','?'):12s}  conf={ld.get('confidence') or '?'}  "
                  f"risk={ld.get('risk_level','?')}  rule_hits={ld.get('rule_hits',0)}  "
                  f"flags={ld.get('url_flags', [])}")

        results.append(result)

    # Summary table
    print("\n" + "=" * 60)
    print("  SUMMARY TABLE")
    print("=" * 60)
    print(f"  {'Case':<28}  {'Avg':>7}  {'P50':>7}  {'P95':>7}  {'Err':>4}")
    print(f"  {'-'*28}  {'-'*7}  {'-'*7}  {'-'*7}  {'-'*4}")
    for r in results:
        print(f"  {r.name:<28}  {r.avg:>6.0f}ms  {r.p50:>6.0f}ms  "
              f"{r.p95:>6.0f}ms  {r.errors:>4}")
    print("=" * 60)

    # Layer cost estimates
    print("\n  ESTIMATED LAYER COSTS (inferred from URL type comparisons):")
    print("  ─────────────────────────────────────────────────────────")

    # Find base: trusted domain (shortest path)
    trusted   = next((r for r in results if "Google" in r.name), None)
    shortener = next((r for r in results if "bit.ly" in r.name), None)
    brand     = next((r for r in results if "Brand" in r.name), None)

    if trusted:
        print(f"  Rule Engine + ML baseline   ≈  {trusted.avg:.0f}ms  (trusted domain, no WHOIS)")
    if shortener and trusted:
        overhead = shortener.avg - trusted.avg
        print(f"  URL Expander overhead       ≈  {max(0,overhead):.0f}ms")
    if brand and trusted:
        overhead = brand.avg - trusted.avg
        print(f"  Visual Similarity overhead  ≈  {max(0,overhead):.0f}ms")

    print()
    return results

def main():
    parser = argparse.ArgumentParser(description="PhishNet ML Pipeline Micro-Benchmark")
    parser.add_argument("--flask-url", default="http://localhost:5002")
    parser.add_argument("--runs",      type=int, default=10)
    args = parser.parse_args()
    run_benchmark(args.flask_url, args.runs)

if __name__ == "__main__":
    main()
