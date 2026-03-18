# 🧠 Deep Dive: PhishNet Adversarial & Intelligence Module

This documentation focuses specifically on the **Adversarial Defense and Intelligence Correlation** module—the most sophisticated layer of the PhishNet system, designed to provide "Nation-State Resistance."

---

## 🏗️ 1. ML Robustness & Adversarial Engine (`adversarial_engine.py`)

### **What was built**
A specialized diagnostic engine that evaluates the "brittleness" of a model's prediction. It determines if a result is genuine or the product of an attacker fine-tuning features to "ride the decision boundary."

### **How it works**
-   **Feature Perturbation**: For every scan, the engine generates slightly modified versions of the extracted features (e.g., varying the URL entropy or DOM counts by ±5%).
-   **Stability Scoring**: It passes these "perturbed" versions through the model. If the prediction flips from "Phishing" to "Legitimate," it assigns a low **Stability Score**.
-   **Semantic Embedding Extraction**: It extracts a high-dimensional vector from the ensemble's internal representation, providing a semantic "fingerprint" of the site's intent that is independent of its domain or IP.

### **Tools and Technologies**
-   **Numpy / Scikit-Learn**: For fast vector operations and perturbation generation.
-   **LightGBM/SHAP Integration**: To understand which feature variances most impact the prediction stability.

### **Reasoning & Decisions**
-   **Rationale**: Standard accuracy metrics are useless against "Adversarial Examples." By measuring stability, we can identify evasion attempts even if our model technically labels them as "Legitimate."

---

## 🕵️ 2. Behavioral Intent Analyzer (`behavioralAnalyzer.js`)

### **What was built**
A heuristic intelligence unit that analyzes the *user's behavior* to distinguish between a casual user and an automated threat actor probing the system.

### **How it works**
-   **Scan Velocity Tracking**: Aggregates scan counts per hardware fingerprint over a 60-second window.
-   **Domain Breadth**: Tracks how many unique TLDs and domains a single fingerprint has scanned in the last hour.
-   **Threat Actor Likelihood (TAL)**: A weighted score where:
    -   Velocity > 10 scans/min = +40 TAL
    -   Unique Domains > 20 = +30 TAL
    -   High-Risk IP/Proxy = +30 TAL

### **Reasoning & Decisions**
-   **Decision**: Blocking IPs is ineffective (attackers use VPNs). We track the **Hardware Fingerprint**, which is much harder to falsify at scale.
-   **Trade-off**: High-velocity researchers might be flagged. *Mitigation*: We only "Audit" and "Notify" at this stage, rather than hard-blocking, to preserve UX for legitimate power users.

---

## 🧪 3. Adversarial Retraining Pipeline (`retrain_adversarial.py`)

### **What was built**
An automated "Hardening Pipeline" that prepares PhishNet for future evasion benchmarks (2026-gen PhaaS techniques).

### **How it works**
-   **Synthetic Evasion Injection**: It takes known phishing data and synthetically "stealthifies" it (e.g., reducing the number of suspicious JS tags) to mimic 2026-style kits.
-   **Hardened Training**: Re-trains the ensemble (LightGBM/CatBoost) on this "hardened" dataset, forcing the model to find deeper, more resilient markers that cannot be easily spoofed.

---

## 🛡️ 4. Outlier Gate & Audit Log (`ScanHistory` / `AuditLog`)

### **What was built**
The "Operational Hygiene" layer that protects the data integrity and provides a forensic trail.

### **How it works**
-   **The Outlier Gate**: If the ML Stability Score < 0.4, the scan is marked as `isOutlier: true`. These scans are excluded from any automated "self-learning" or retraining pipelines.
-   **The Audit Log**: High-risk events (Threat Actor Likelihood > 70%) are instantly recorded into an immutable, TTL-indexed table for administrative review.

---

## 🎤 Defense Statement: "How do you stop model poisoning?"
*"PhishNet implements an 'Anti-Poisoning Gateway.' Every submission is analyzed by our Adversarial Engine for prediction stability. If an attacker submits a 'borderline' sample designed to bias our next training cycle, our Outlier Gate detects the high instability, flags the result as a potential evasion attempt, and isolates it from our training repository. We don't just learn from data; we verify the integrity of every data point before it enters our system."*
