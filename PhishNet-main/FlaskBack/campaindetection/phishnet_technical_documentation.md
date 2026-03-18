# 📄 PhishNet: Technical Architecture & Defense Documentation

This document provides a comprehensive technical breakdown of the PhishNet Phishing Detection & Intelligence System. It is structured to support a rigorous academic or professional defense, covering every layer from the ML ensemble to the hardened analysis infrastructure.

-   **Unified Phishing Detection Ensemble (ML)**: LightGBM, CatBoost, and XGBoost models.
-   **Adversarial & Robustness Engine**: Certified stability scoring and semantic embeddings.
-   **Hardened Infrastructure**: Single-resolution DNS fetcher, PoW, and fingerprinting defenses.
-   **Chrome Browser Extension**: Real-time browser-level protection and telemetry capture.
-   **Campaign & Intelligence Feed**: Real-time clustering and visualization system.
-   **Data Harvesting & Pipeline**: Automated scraping and dataset expansion workflow.

---

## 🏗️ 1. The Machine Learning Brain (High-Precision Ensemble)

### **What was built**
A multi-layered machine learning pipeline that fuses heuristic rule engines with a high-performance ensemble of Gradient Boosted Decision Trees (GBDTs). It doesn't just predict "Phishing" or "Legitimate"; it provides a quantified risk score backed by explainable AI (XAI).

### **How it works**
1.  **Feature Extraction**: Over 100 features are extracted from a URL, including DOM structure, SSL metadata, URL entropy, and lexical patterns.
2.  **The Ensemble**: Three models—**LightGBM, CatBoost, and XGBoost**—provide independent predictions.
3.  **Intelligent Fusion**: A voting mechanism determines the final verdict. If the models disagree, the system reverts to a high-precision "Robustness" check.
4.  **Explainability**: Uses **SHAP (SHapley Additive exPlanations)** to generate a report showing *why* a URL was flagged (e.g., "Flagged due to high URL entropy and missing favicon").

### **Tools and Technologies**
- **LightGBM / XGBoost / CatBoost**: Chosen for their superior performance on tabular data and ability to handle imbalanced datasets better than traditional Neural Networks.
- **SHAP**: For model transparency—critical for user trust and forensic analysis.
- **Flask**: Serves as the high-speed Python interface for the ML pipeline.

### **Reasoning & Decisions**
- **Decision vs. Neural Networks**: For phishing detection (which is primarily tabular/numeric features), GBDTs are more interpretable and faster than Deep Learning.
- **Ensemble vs. Single Model**: Attackers often optimize for one model; fooling three distinct architectures simultaneously is an order of magnitude harder.

---

## 🛡️ 2. The Adversarial Shield (Hardened Analysis)

### **What was built**
A "battle-tested" fetching and security layer designed to prevent the analyzer itself from being attacked by sophisticated adversaries.

### **How it works**
-   **Hardened Fetcher**: Implements single-resolution DNS fetching. It resolves an IP, validates it against CIDR blacklists (preventing SSRF), and then fetches the content *only from that IP*. This kills **DNS Rebinding** attacks at the root.
-   **Proof-of-Work (PoW)**: Every scan request requires a client-side cryptographic puzzle (m-CAPTCHA style). 
-   **Hardware Fingerprinting**: Uses Canvas and WebGL traits to identify the hardware signature of the client, bypassing simple IP or User-Agent rotation.

### **Tools and Technologies**
-   **Crypto.js**: Used for the PoW challenge-response logic.
-   **Axios / Hardened Python Requests**: Custom-wrapped to handle Host-header injection and single-resolution routing.

### **Reasoning & Decisions**
-   **Why PoW?**: Standard CAPTCHAs are solved by "click farms." A PoW challenge forces the attacker's CPU to work. It makes automated "model probing" or "feedback oracle" attacks economically unfeasible.
-   **Why Fingerprinting?**: Advanced attackers rotate IPs via VPNs. Hardware fingerprinting allows us to identify when a single actor is using multiple accounts or locations.

---

## 📡 3. The Detective (Campaign Correlation Engine)

### **What was built**
A real-time intelligence engine that identifies when disparate phishing attempts are actually part of a coordinated, global campaign.

### **How it works**
1.  **Signature Extraction**: Every scan generates a "Campaign Signature" consisting of:
    -   HTML Structure Hash (DOM similarity)
    -   Server Infrastructure (IP/Network)
    -   **Semantic Embeddings**: High-dimensional vectors derived from the ML model's internal state.
2.  **Clustering**: The system uses these signatures to link URLs. Even if the attacker changes the domain and IP, the **Semantic Embedding** remains similar if the underlying "kit" is the same.
3.  **Real-Time Push**: Correlated detections are pushed to the **Intelligence Dashboard** via WebSockets (Socket.IO).

### **Tools and Technologies**
-   **Socket.IO**: For sub-millisecond updates to the dashboard.
-   **Mongoose/MongoDB**: Stores campaign history and handles fast similarity lookups.

### **Reasoning & Decisions**
-   **Embeddings vs. Simple Hashes**: Attackers can change a single character in HTML to break a hash. Semantic embeddings capture the "intent" and "style" of the page, making them resilient to minor obfuscation.

---

## 🧠 4. Behavioral Intelligence & Outlier Gate

### **What was built**
A secondary defense layer focused on identifying the *actor* rather than just the *URL*.

### **How it works**
-   **Behavioral Analyzer**: Tracks scan velocity (scans/min) and domain breadth. A user scanning 50 different domains in 1 minute is flagged as a high-risk automated actor.
-   **Adversarial Engine & Outlier Gate**: After a prediction, the `AdversarialEngine` applies perturbations to the features. If the model's prediction flips easily (low stability), the scan is flagged as an `isOutlier` and isolated from the training system to prevent **Dataset Poisoning**.

### **Tools and Technologies**
-   **AuditLog (Immutable)**: A database-backed record of every high-risk event.
-   **Scikit-Learn**: Used for generating feature perturbations during the robustness check.

### **Reasoning & Decisions**
-   **Why the Outlier Gate?**: Sophisticated attackers submit "adversarial examples" to public dashboards to poison the next version of the model. By flagging unstable results, we ensure our "self-learning" loop stays clean.

---

## 🗺️ 5. Integration: How it all connects

1.  **Input**: User submits a URL on the React frontend.
2.  **Gate 1**: The frontend solves a **PoW** and captures a **Fingerprint**.
3.  **Gate 2**: The Node.js backend validates the PoW and runs the **Behavioral Analyzer**. 
4.  **Gate 3**: If clear, the Flask service uses the **HardenedFetcher** to get the content safely.
5.  **Gate 4**: ML Models predict the risk, and the **AdversarialEngine** scores the stability.
6.  **Gate 5**: The **Correlation Engine** links the scan to an active **Campaign**.
7.  **Output**: Results are saved to **ScanHistory**, and a real-time update is pushed to the **Intelligence Dashboard**.

---

## 🌐 6. Chrome Browser Extension (Browser Protection)

### **What was built**
A lightweight browser extension that provides real-time protection and active telemetry for the PhishNet ecosystem.

### **How it works**
1.  **Passive Monitoring**: Intercepts `onBeforeRequest` and `onDOMContentLoaded` events to identify potential threats before they load.
2.  **Visual Overlays**: Injects a specialized status bar (Safe, Suspicious, or Phishing) directly into the page DOM.
3.  **Active Telemetry**: Captures "In-the-Wild" markers (e.g., hidden redirection chains) and sends them to the PhishNet backend for analysis.

### **Reasoning & Decisions**
-   **Why an extension?**: Many phishing kits use "Client-Side Cloaking" (scripts that only run in a real browser). An extension sees exactly what the user sees, whereas server-side fetchers can be easily blocked or "cloaked."

---

## 🏗️ 7. Data Collection & Training Workflow

### **What was built**
The "Feeding System" for the ML ensemble, ensuring the model evolves with the threat landscape.

### **How it works**
1.  **Source Fusing**: Aggregates URLs from OpenPhish, PhishTank, and our internal honeypots.
2.  **Dataset Expansion (`expand_dataset.py`)**: Automates the scraping of legitimate domains to maintain a balanced training ratio (essential for avoiding False Positives).
3.  **Optimization Pipeline**: Uses **Optuna** to find the absolute best hyperparameters for the LightGBM and CatBoost models, aiming for a G-Mean > 99.99%.

### **Reasoning & Decisions**
-   **Why Optuna?**: Manual tuning is prone to human bias and overfitting. Automated Bayesian optimization ensures we find the "Global Optimum" for detection precision.
-   **URLSimilarityIndex Removal**: In our training, we explicitly removed this feature to prevent "Data Leakage," where the model learns the test-set identifiers instead of actual phishing patterns.

---

## 🎤 Final Defense Statement: "Is this ready for deployment?"
*"PhishNet is not just a classifier; it is a hardened intelligence ecosystem. While standard systems are vulnerable to SSRF, adversarial evasion, and bot-based extraction, PhishNet implements single-resolution DNS fetching, cryptographic Proof-of-Work, and certified robustness evaluation. It doesn't just block a URL—it detects the campaign, identifies the actor's behavior, and protects its own internal models from corruption."*
