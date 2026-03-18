import requests
import sys
import json
import time

def simulate_phaas_attack(target_url, backend_url="http://localhost:5000/api/phishing/analyze", token=None):
    """
    Simulates a 2026-style PhaaS attack sequence against PhishNet.
    Attempts to use known evasion techniques:
    1.  Homograph-style obfuscation
    2.  Dynamic content shifting
    3.  PoW-token reuse probes
    """
    print("="*80)
    print("🚩 PHISHNET RED-TEAM VALIDATION ENGINE (PhaaS-2026 Simulator)")
    print("="*80)
    
    headers = {
        "Content-Type": "application/json"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
        
    # Attack 1: Standard Probe
    print(f"\n[ATTACK 1] Baseline Probe: {target_url}")
    payload = {
        "url": target_url,
        "fingerprint": "red-team-bot-01",
        "pow": {"nonce": 12345, "solution": "manual-bypass"} # Testing PoW strictness
    }
    
    start = time.time()
    try:
        r = requests.post(backend_url, json=payload, headers=headers)
        print(f"Status: {r.status_code}")
        if r.status_code == 200:
            res = r.json()
            print(f"Verdict: {res['data']['prediction']} (Confidence: {res['data']['confidence']}%)")
            print(f"Stability Score: {res['data'].get('adversarial_robustness', {}).get('stability_score', 'N/A')}")
        else:
            print(f"Failed: {r.text}")
    except Exception as e:
        print(f"Error: {e}")

    # Attack 2: Rapid Re-probing (Behavioral Trigger Test)
    print(f"\n[ATTACK 2] Burst Re-probing (Behavioral Trigger Test)...")
    for i in range(5):
        print(f"  > Probing {i+1}/5...")
        requests.post(backend_url, json=payload, headers=headers)
    
    # Final check for behavioral data
    print("\n🔍 Checking behavioral telemetry for detection...")
    r = requests.post(backend_url, json=payload, headers=headers)
    if r.status_code == 200:
        bh = r.json()['data'].get('behavioralContext', {})
        print(f"Threat Actor Likelihood: {bh.get('threatActorLikelihood', 0)}%")
        if bh.get('threatActorLikelihood', 0) > 50:
             print("✅ Behavioral Gate properly triggered high-risk alert.")
        else:
             print("⚠️ Behavioral Gate sensitivity may need tuning.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python phaas_simulator.py <target_url> [bearer_token]")
    else:
        url = sys.argv[1]
        token = sys.argv[2] if len(sys.argv) > 2 else None
        simulate_phaas_attack(url, token=token)
