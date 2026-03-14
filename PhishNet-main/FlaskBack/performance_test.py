"""
PhishNet Performance Test Suite
================================
Tests: Latency · Throughput · Concurrency · Load · Stress · Spike

Usage:
  # Via Express (JWT login required)
  python performance_test.py --email user@test.com --password yourpass

  # Bypass Express, hit Flask directly (no auth needed)
  python performance_test.py --flask-only

  # Run a specific suite
  python performance_test.py --flask-only --suite baseline
  python performance_test.py --email u@t.com --password p --suite load --users 20 --duration 60
"""

import asyncio
import time
import statistics
import json
import argparse
import csv
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional
import aiohttp
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────────────

BASE_URL   = "http://localhost:8800"
FLASK_URL  = "http://localhost:5002"
TIMEOUT    = 35
REPORT_DIR = "reports"

TEST_URLS = {
    "legitimate": [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.wikipedia.org",
        "https://www.stackoverflow.com",
        "https://www.linkedin.com",
        "https://www.youtube.com",
    ],
    "phishing": [
        "http://192.168.1.1/login",
        "http://paypal-secure-update.xyz/verify",
        "http://amazon-account-suspended.com/login",
        "http://bit.ly/phish-test-url",
        "http://apple-id-locked.info/unlock",
        "http://secure-bankofamerica.net/login",
    ],
    "edge_cases": [
        "http://xn--pple-43d.com",
        "http://www.g00gle.com",
        "https://legit.com/very/" + "a" * 100,
        "http://user@192.168.0.1/page",
        "https://sub.sub.sub.sub.legit.com",
    ],
}

ALL_URLS = (
    TEST_URLS["legitimate"]
    + TEST_URLS["phishing"]
    + TEST_URLS["edge_cases"]
)


# ─────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────

def login(base_url: str, email: str, password: str) -> requests.Session:
    """
    POST to /api/auth/login, store the JWT cookie in a session.
    Returns a requests.Session with the cookie set, or raises on failure.
    """
    session = requests.Session()
    login_url = f"{base_url}/api/auth/login"
    print(f"\n  Logging in as {email} → {login_url}")
    try:
        resp = session.post(
            login_url,
            json={"email": email, "password": password},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            # Some setups return the token in the body instead of a cookie
            token = data.get("token") or data.get("accessToken") or data.get("jwt")
            if token:
                session.headers.update({"Authorization": f"Bearer {token}"})
                print(f"  Login OK — token stored in Authorization header")
            else:
                print(f"  Login OK — JWT cookie stored (withCredentials mode)")
            return session
        else:
            print(f"  Login FAILED — {resp.status_code}: {resp.text[:200]}")
            raise SystemExit(
                "\n  Cannot run Express tests without a valid JWT.\n"
                "  Options:\n"
                "    1. Fix credentials: --email <e> --password <p>\n"
                "    2. Bypass Express:  --flask-only\n"
            )
    except requests.exceptions.ConnectionError:
        raise SystemExit(
            f"\n  Cannot connect to {login_url}.\n"
            "  Is Express running?  Try --flask-only to test Flask directly.\n"
        )


# ─────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────

@dataclass
class RequestResult:
    url:         str
    status_code: int
    latency_ms:  float
    success:     bool
    error:       Optional[str] = None
    prediction:  Optional[str] = None
    confidence:  Optional[float] = None


@dataclass
class TestReport:
    test_name:      str
    start_time:     str
    end_time:       str
    duration_sec:   float
    total_requests: int
    successful:     int
    failed:         int
    latencies_ms:   List[float] = field(default_factory=list)

    @property
    def success_rate(self):
        return (self.successful / self.total_requests * 100) if self.total_requests else 0

    @property
    def rps(self):
        return self.total_requests / self.duration_sec if self.duration_sec else 0

    @property
    def p50(self):
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0

    @property
    def p95(self):
        s = sorted(self.latencies_ms)
        return s[int(len(s) * 0.95)] if s else 0

    @property
    def p99(self):
        s = sorted(self.latencies_ms)
        return s[int(len(s) * 0.99)] if s else 0

    @property
    def avg(self):
        return statistics.mean(self.latencies_ms) if self.latencies_ms else 0

    @property
    def min_lat(self):
        return min(self.latencies_ms) if self.latencies_ms else 0

    @property
    def max_lat(self):
        return max(self.latencies_ms) if self.latencies_ms else 0

    def print_summary(self):
        print(f"\n{'='*55}")
        print(f"  {self.test_name}")
        print(f"{'='*55}")
        print(f"  Duration       : {self.duration_sec:.2f}s")
        print(f"  Total Requests : {self.total_requests}")
        print(f"  Successful     : {self.successful}  ({self.success_rate:.1f}%)")
        print(f"  Failed         : {self.failed}")
        print(f"  Throughput     : {self.rps:.2f} req/s")
        print(f"  Latency (ms)   :")
        print(f"    Min          : {self.min_lat:.1f}")
        print(f"    Avg          : {self.avg:.1f}")
        print(f"    P50          : {self.p50:.1f}")
        print(f"    P95          : {self.p95:.1f}")
        print(f"    P99          : {self.p99:.1f}")
        print(f"    Max          : {self.max_lat:.1f}")
        print(f"{'='*55}")


# ─────────────────────────────────────────────────────
# REQUEST HELPERS
# ─────────────────────────────────────────────────────

def sync_request(
    url: str,
    endpoint: str,
    session: Optional[requests.Session] = None,
) -> RequestResult:
    """Single synchronous POST — uses session (with cookie/token) if provided."""
    requester = session or requests
    t0 = time.perf_counter()
    try:
        resp = requester.post(
            endpoint,
            json={"url": url},
            timeout=TIMEOUT,
        )
        latency = (time.perf_counter() - t0) * 1000
        ct = resp.headers.get("content-type", "")
        data = resp.json() if "application/json" in ct else {}
        return RequestResult(
            url=url,
            status_code=resp.status_code,
            latency_ms=latency,
            success=resp.status_code == 200,
            prediction=data.get("prediction"),
            confidence=data.get("confidence"),
        )
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000
        return RequestResult(
            url=url, status_code=0, latency_ms=latency,
            success=False, error=str(e)
        )


async def async_request(
    session: aiohttp.ClientSession,
    url: str,
    endpoint: str,
) -> RequestResult:
    """Single async POST."""
    t0 = time.perf_counter()
    try:
        async with session.post(
            endpoint,
            json={"url": url},
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as resp:
            latency = (time.perf_counter() - t0) * 1000
            data = await resp.json(content_type=None)
            return RequestResult(
                url=url,
                status_code=resp.status,
                latency_ms=latency,
                success=resp.status == 200,
                prediction=data.get("prediction"),
                confidence=data.get("confidence"),
            )
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000
        return RequestResult(
            url=url, status_code=0, latency_ms=latency,
            success=False, error=str(e)
        )


def _pick_endpoint(base_url: str, flask_url: str, flask_only: bool) -> str:
    if flask_only:
        return f"{flask_url}/analyze"
    return f"{base_url}/api/phishing/analyze"


# ─────────────────────────────────────────────────────
# TEST 1 — BASELINE LATENCY
# ─────────────────────────────────────────────────────

def test_baseline_latency(
    endpoint: str,
    session: Optional[requests.Session],
) -> TestReport:
    print("\n[1/6] Running BASELINE LATENCY test...")
    results = []
    t_start = time.perf_counter()

    for url in ALL_URLS:
        result = sync_request(url, endpoint, session)
        results.append(result)
        if result.success:
            tag = f"{result.prediction or 'ok':12s}  conf={result.confidence or '?'}"
        else:
            tag = f"FAIL({result.error or result.status_code})"
        print(f"  {tag:40s}  {result.latency_ms:7.1f}ms  {url[:50]}")

    t_end = time.perf_counter()
    report = TestReport(
        test_name="Baseline Latency",
        start_time=datetime.now().isoformat(),
        end_time=datetime.now().isoformat(),
        duration_sec=t_end - t_start,
        total_requests=len(results),
        successful=sum(1 for r in results if r.success),
        failed=sum(1 for r in results if not r.success),
        latencies_ms=[r.latency_ms for r in results],
    )
    report.print_summary()
    return report


# ─────────────────────────────────────────────────────
# TEST 2 — THROUGHPUT
# ─────────────────────────────────────────────────────

def test_throughput(
    endpoint: str,
    session: Optional[requests.Session],
    num_requests: int = 50,
) -> TestReport:
    print(f"\n[2/6] Running THROUGHPUT test ({num_requests} requests)...")
    urls    = (ALL_URLS * (num_requests // len(ALL_URLS) + 1))[:num_requests]
    results = []
    t_start = time.perf_counter()

    for i, url in enumerate(urls):
        result = sync_request(url, endpoint, session)
        results.append(result)
        if (i + 1) % 10 == 0:
            elapsed = time.perf_counter() - t_start
            rps     = (i + 1) / elapsed
            avg     = statistics.mean(r.latency_ms for r in results)
            print(f"  Progress: {i+1}/{num_requests}  |  {rps:.2f} req/s  |  avg {avg:.0f}ms")

    t_end = time.perf_counter()
    report = TestReport(
        test_name=f"Throughput ({num_requests} requests)",
        start_time=datetime.now().isoformat(),
        end_time=datetime.now().isoformat(),
        duration_sec=t_end - t_start,
        total_requests=len(results),
        successful=sum(1 for r in results if r.success),
        failed=sum(1 for r in results if not r.success),
        latencies_ms=[r.latency_ms for r in results],
    )
    report.print_summary()
    return report


# ─────────────────────────────────────────────────────
# TEST 3 — CONCURRENCY
# ─────────────────────────────────────────────────────

def test_concurrency(
    endpoint: str,
    session: Optional[requests.Session],
    levels: List[int] = [1, 5, 10, 20, 50],
) -> List[TestReport]:
    print(f"\n[3/6] Running CONCURRENCY test (levels: {levels})...")
    reports = []

    for level in levels:
        print(f"\n  -- Concurrency = {level} --")
        urls    = (ALL_URLS * (level // len(ALL_URLS) + 1))[:level]
        results = []
        t_start = time.perf_counter()

        with ThreadPoolExecutor(max_workers=level) as ex:
            futures = {
                ex.submit(sync_request, url, endpoint, session): url
                for url in urls
            }
            for future in as_completed(futures):
                results.append(future.result())

        t_end = time.perf_counter()
        ok    = sum(1 for r in results if r.success)
        avg   = statistics.mean(r.latency_ms for r in results)
        print(f"  ok={ok}/{level}  avg={avg:.0f}ms  elapsed={t_end-t_start:.2f}s")

        reports.append(TestReport(
            test_name=f"Concurrency (n={level})",
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            duration_sec=t_end - t_start,
            total_requests=len(results),
            successful=ok,
            failed=level - ok,
            latencies_ms=[r.latency_ms for r in results],
        ))

    for r in reports:
        r.print_summary()
    return reports


# ─────────────────────────────────────────────────────
# TEST 4 — LOAD (async sustained)
# ─────────────────────────────────────────────────────

async def _load_worker(session, endpoint, results, duration_sec):
    deadline = time.perf_counter() + duration_sec
    idx      = 0
    while time.perf_counter() < deadline:
        url    = ALL_URLS[idx % len(ALL_URLS)]
        result = await async_request(session, url, endpoint)
        results.append(result)
        idx   += 1


async def _run_load(endpoint: str, auth_headers: dict,
                    concurrent_users: int, duration_sec: int):
    results = []
    async with aiohttp.ClientSession(headers=auth_headers) as session:
        await asyncio.gather(*[
            _load_worker(session, endpoint, results, duration_sec)
            for _ in range(concurrent_users)
        ])
    return results


def test_load(
    endpoint: str,
    auth_headers: dict,
    concurrent_users: int = 10,
    duration_sec: int     = 30,
) -> TestReport:
    print(f"\n[4/6] Running LOAD test ({concurrent_users} users, {duration_sec}s)...")
    t_start = time.perf_counter()
    results = asyncio.run(_run_load(endpoint, auth_headers, concurrent_users, duration_sec))
    t_end   = time.perf_counter()

    report = TestReport(
        test_name=f"Load ({concurrent_users} users, {duration_sec}s)",
        start_time=datetime.now().isoformat(),
        end_time=datetime.now().isoformat(),
        duration_sec=t_end - t_start,
        total_requests=len(results),
        successful=sum(1 for r in results if r.success),
        failed=sum(1 for r in results if not r.success),
        latencies_ms=[r.latency_ms for r in results],
    )
    report.print_summary()
    return report


# ─────────────────────────────────────────────────────
# TEST 5 — STRESS (ramp until breaking point)
# ─────────────────────────────────────────────────────

def test_stress(
    endpoint: str,
    session: Optional[requests.Session],
    max_concurrent: int = 100,
    step: int           = 10,
) -> TestReport:
    print(f"\n[5/6] Running STRESS test (ramp to {max_concurrent} users)...")
    all_results = []
    breaking    = None

    for level in range(step, max_concurrent + 1, step):
        urls = (ALL_URLS * (level // len(ALL_URLS) + 1))[:level]
        with ThreadPoolExecutor(max_workers=level) as ex:
            futures = [ex.submit(sync_request, url, endpoint, session) for url in urls]
            batch   = [f.result() for f in as_completed(futures)]

        all_results.extend(batch)
        err_rate = sum(1 for r in batch if not r.success) / len(batch) * 100
        avg_lat  = statistics.mean(r.latency_ms for r in batch)
        print(f"  n={level:3d}  |  err={err_rate:.1f}%  |  avg={avg_lat:.0f}ms")

        if err_rate > 10 or avg_lat > 10_000:
            breaking = level
            print(f"\n  *** BREAKING POINT at n={level} — err={err_rate:.1f}%, avg={avg_lat:.0f}ms ***")
            break

    if not breaking:
        print(f"\n  System stable up to n={max_concurrent}.")

    report = TestReport(
        test_name=f"Stress (max={max_concurrent})",
        start_time=datetime.now().isoformat(),
        end_time=datetime.now().isoformat(),
        duration_sec=0,
        total_requests=len(all_results),
        successful=sum(1 for r in all_results if r.success),
        failed=sum(1 for r in all_results if not r.success),
        latencies_ms=[r.latency_ms for r in all_results],
    )
    report.print_summary()
    return report


# ─────────────────────────────────────────────────────
# TEST 6 — SPIKE
# ─────────────────────────────────────────────────────

def test_spike(
    endpoint: str,
    session: Optional[requests.Session],
) -> TestReport:
    print("\n[6/6] Running SPIKE test...")
    all_results = []

    phases = [
        ("Normal  (5 users) ", 5),
        ("SPIKE   (50 users)", 50),
        ("Normal  (5 users) ", 5),
    ]

    for phase_name, level in phases:
        urls = (ALL_URLS * (level // len(ALL_URLS) + 1))[:level]
        t0   = time.perf_counter()
        with ThreadPoolExecutor(max_workers=level) as ex:
            futures = [ex.submit(sync_request, url, endpoint, session) for url in urls]
            batch   = [f.result() for f in as_completed(futures)]
        elapsed  = time.perf_counter() - t0
        all_results.extend(batch)
        err_rate = sum(1 for r in batch if not r.success) / len(batch) * 100
        avg_lat  = statistics.mean(r.latency_ms for r in batch)
        print(f"  {phase_name}  |  {elapsed:.2f}s  |  err={err_rate:.1f}%  |  avg={avg_lat:.0f}ms")

    report = TestReport(
        test_name="Spike Test",
        start_time=datetime.now().isoformat(),
        end_time=datetime.now().isoformat(),
        duration_sec=0,
        total_requests=len(all_results),
        successful=sum(1 for r in all_results if r.success),
        failed=sum(1 for r in all_results if not r.success),
        latencies_ms=[r.latency_ms for r in all_results],
    )
    report.print_summary()
    return report


# ─────────────────────────────────────────────────────
# REPORT WRITERS
# ─────────────────────────────────────────────────────

def write_csv(reports: List[TestReport], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Test", "Duration(s)", "Total", "OK", "Fail",
                    "Success%", "RPS", "Min(ms)", "Avg(ms)",
                    "P50(ms)", "P95(ms)", "P99(ms)", "Max(ms)"])
        for r in reports:
            w.writerow([
                r.test_name, f"{r.duration_sec:.2f}", r.total_requests,
                r.successful, r.failed, f"{r.success_rate:.1f}",
                f"{r.rps:.2f}", f"{r.min_lat:.1f}", f"{r.avg:.1f}",
                f"{r.p50:.1f}", f"{r.p95:.1f}", f"{r.p99:.1f}", f"{r.max_lat:.1f}",
            ])
    print(f"\n  CSV  → {path}")


def write_json(reports: List[TestReport], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = [{
        "test_name":        r.test_name,
        "duration_sec":     round(r.duration_sec, 3),
        "total_requests":   r.total_requests,
        "successful":       r.successful,
        "failed":           r.failed,
        "success_rate_pct": round(r.success_rate, 2),
        "rps":              round(r.rps, 2),
        "latency_ms": {
            "min": round(r.min_lat, 1),
            "avg": round(r.avg, 1),
            "p50": round(r.p50, 1),
            "p95": round(r.p95, 1),
            "p99": round(r.p99, 1),
            "max": round(r.max_lat, 1),
        },
    } for r in reports]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  JSON → {path}")


# ─────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PhishNet Performance Test Suite")
    parser.add_argument("--base-url",   default=BASE_URL)
    parser.add_argument("--flask-url",  default=FLASK_URL)

    # Auth — required for Express routes, skip with --flask-only
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--flask-only",  action="store_true",
                      help="Bypass Express, hit Flask :5002 directly (no auth needed)")
    auth.add_argument("--email",       default="",
                      help="Account email for JWT login")
    parser.add_argument("--password",  default="",
                      help="Account password for JWT login")

    parser.add_argument("--suite",      default="all",
        choices=["all","baseline","throughput","concurrency","load","stress","spike"])
    parser.add_argument("--requests",  type=int, default=50)
    parser.add_argument("--users",     type=int, default=10)
    parser.add_argument("--duration",  type=int, default=30)
    parser.add_argument("--max-stress",type=int, default=100)
    args = parser.parse_args()

    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Resolve endpoint + auth ──────────────────────
    if args.flask_only:
        endpoint     = f"{args.flask_url}/analyze"
        session      = None
        auth_headers = {}
        mode         = "Flask direct (no auth)"
    elif args.email and args.password:
        endpoint     = f"{args.base_url}/api/phishing/analyze"
        session      = login(args.base_url, args.email, args.password)
        auth_headers = dict(session.headers)
        mode         = f"Express via JWT ({args.email})"
    else:
        # Default: hit Flask directly
        endpoint     = f"{args.flask_url}/analyze"
        session      = None
        auth_headers = {}
        mode         = "Flask direct (no auth) — default"

    print("=" * 55)
    print("  PhishNet Performance Test Suite")
    print(f"  Mode   : {mode}")
    print(f"  Target : {endpoint}")
    print(f"  Suite  : {args.suite}")
    print("=" * 55)

    all_reports: List[TestReport] = []
    s = args.suite

    if s in ("all", "baseline"):
        all_reports.append(test_baseline_latency(endpoint, session))

    if s in ("all", "throughput"):
        all_reports.append(test_throughput(endpoint, session, args.requests))

    if s in ("all", "concurrency"):
        all_reports.extend(test_concurrency(endpoint, session))

    if s in ("all", "load"):
        all_reports.append(test_load(endpoint, auth_headers, args.users, args.duration))

    if s in ("all", "stress"):
        all_reports.append(test_stress(endpoint, session, args.max_stress))

    if s in ("all", "spike"):
        all_reports.append(test_spike(endpoint, session))

    write_csv(all_reports,  f"{REPORT_DIR}/perf_report_{ts}.csv")
    write_json(all_reports, f"{REPORT_DIR}/perf_report_{ts}.json")
    print("\n  Done.")


if __name__ == "__main__":
    main()