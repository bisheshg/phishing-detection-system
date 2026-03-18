# 📡 Module Documentation: Real-Time Intelligence & Campaign Correlation

This document provides a deep-dive technical explanation of the PhishNet **Real-Time Intelligence Dashboard** and the **Campaign Correlation Engine**. This module transforms individual URL scans into high-level threat intelligence.

---

## 🏗️ 1. Campaign Correlation Engine (The "Clusterer")

### **What was built**
A backend logic system that automatically groups individual phishing detections into "Campaigns." It identifies when different URLs are controlled by the same actor or kit.

### **How it works**
When a URL is analyzed, the system generates a **Multi-Factor Campaign Signature**:
1.  **HTML Structure Hash**: A fuzzy hash of the DOM (Document Object Model) structure. If two sites look identical but have different text/images, the hash remains the same.
2.  **Server Infrastructure (IP)**: The hosting server's IP. This links attacks coming from the same VPS.
3.  **Semantic Embeddings**: The most advanced factor. This is a high-dimensional vector derived from the ML model's internal representation. It captures the "style" and "intent" of the attack.

**The Logic**: If a new detection matches *any* of these factors, it is added to an existing "Active" campaign. If not, a new campaign is born.

### **Reasoning & Decisions**
*   **Why not just use the Domain?** Attackers rotate domains every few hours (Domain Generation Algorithms - DGAs). Tracking by domain is useless.
*   **Why Semantic Embeddings?** To counter **"Infrastructure Hopping."** An attacker might change their HTML hash (by adding junk code) and their IP (by moving to a new server). However, the *semantic nature* of their attack (how the landing page behaves) often stays consistent.

---

## 📡 2. Real-Time Push Architecture (Socket.IO)

### **What was built**
A low-latency message bus that connects the analysis backend directly to the user's dashboard without requiring a page refresh.

### **How it works**
1.  **The Trigger**: Immediately after a scan is saved and linked to a campaign in the database, the backend calls `io.emit("new_detection", ...)`.
2.  **The Payload**: The push message includes the URL, Risk Level, Confidence, and most importantly, the **Campaign ID**.
3.  **The Receiver**: The React frontend listens for this event and updates the live feed dynamically.

### **Tools and Technologies**
*   **Socket.IO**: Chosen over raw WebSockets because it handles reconnection, buffering, and fallback (polling) automatically if the connection is unstable.

### **Reasoning & Decisions**
*   **Polling vs. Push**: Standard AJAX polling (asking the server for updates every 5 seconds) creates unnecessary load and introduces lag. Socket.IO provides **Push-on-Detection**, which is more efficient and provides a better user experience.

---

## 📊 3. Live Intelligence Dashboard (Frontend UI)

### **What was built**
A sophisticated, glassmism-styled React page that provides a "Tactical Overview" of global phishing threats.

### **How it works**
*   **Live Feed**: A scrolling list of detections as they happen globally.
*   **Campaign Correlation View**: A list of "Coordinated Threats" showing how many URLs are linked to a specific campaign actor.
*   **Threat Meter**: A visual representation of current global risk (e.g., "Critical" if multiple high-confidence campaigns are active).

### **Tools and Technologies**
*   **React Context/State**: Manages the incoming stream of real-time data.
*   **Tailwind CSS / Glassmorphism**: For a premium, state-of-the-art visual aesthetic.
*   **React Icons**: For rapid identification of threat categories.

---

## 🗺️ 4. System Integration: The Data Journey

1.  **Phishing Detected**: The Flask ML service identifies a new threat.
2.  **Signature Generated**: The backend extracts the HTML hash and IP.
3.  **Correlation Check**: `phishing.js` queries MongoDB: *"Is there an active campaign with this hash, IP, or semantic embedding?"*
4.  **Database Update**: The URL is linked to the campaign. Total hits for that campaign are incremented.
5.  **Broadcast**: Socket.IO sends the packet: `new_detection -> Dashboard`.
6.  **Visualization**: The dashboard's state updates, and the user sees the new node appearing in real time.

---

## 🎤 Defense Statement: "How did you build it?"
*"We built a real-time correlation engine that moves beyond simple blacklisting. By fusing infrastructure signatures with high-dimensional semantic embeddings, we can track coordinated phishing campaigns as they move across domains and hosting providers. This intelligence is pushed to our live dashboard using a Socket.IO event bus, allowing security operators to see global phishing patterns emerge in sub-millisecond real time. It is the transition from individual detection to collective intelligence."*
