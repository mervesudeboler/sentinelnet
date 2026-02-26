# ⬡ SentinelNet

> AI-powered network intrusion detection that **learns from your own traffic**.  
> Real-time monitoring · Live dashboard · Adaptive ML model · Zero config needed.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange?logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## What makes SentinelNet different?

Most IDS tools use static models trained on old datasets. SentinelNet starts with a **pre-trained baseline** (97%+ accuracy) and then **continuously learns from your network** — improving every packet it sees. The longer it runs, the smarter it gets.

---

## Features

| Feature | Description |
|---|---|
| **Adaptive AI Model** | Starts smart, gets smarter. Learns your traffic patterns over time |
| **Live Web Dashboard** | Real-time charts, packet feed, and alert timeline in your browser |
| **Real Network Capture** | Uses Scapy to capture actual packets on your interface |
| **Demo Mode** | Try it without root — simulated traffic, full dashboard |
| **Attack Detection** | DoS/DDoS, Port Scan, Brute-Force, and Anomalies |
| **Persistent Learning** | Model state saved between sessions — doesn't forget |
| **Alert Reports** | Download CSV or JSON reports of detected attacks |
| **Severity Levels** | LOW / MEDIUM / HIGH classification per alert |

---

## Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/mervesudeboler/sentinelnet.git
cd sentinelnet
python3 setup.py
```

### 2. Try Demo Mode (no root needed)
```bash
python3 main.py --demo
```

### 3. Live Monitoring (your real network)
```bash
# First, find your interface
python3 main.py --list-interfaces

# Then start monitoring
sudo python3 main.py --interface en0
```

### 4. Open Dashboard
```
http://localhost:5000
```

---

## CLI Options

| Flag | Description |
|---|---|
| `--interface en0` | Network interface to monitor |
| `--demo` | Simulated traffic, no root required |
| `--port 8080` | Custom dashboard port (default: 5000) |
| `--list-interfaces` | Show available network interfaces |
| `--reset-model` | Forget learned data, start fresh |
| `--log-level DEBUG` | Verbose logging |

---

## How the AI Works

### Two-Stage Adaptive Architecture

```
Incoming Packet
      │
      ▼
Feature Extraction (14 features)
      │
      ├──► Baseline Random Forest  ──┐
      │    (pre-trained, 97%+ acc)   │
      │                              ├──► Ensemble Prediction
      └──► Online SGD Classifier  ──┘    (weighted blend)
           (learns from YOUR traffic)
                │
                ▼
           observe() ──► partial_fit() every 10 packets
```

**Stage 1 — Baseline RF:** A Random Forest trained on 8,000 synthetic flows.  
Works from the first packet with high accuracy.

**Stage 2 — Online SGD:** An incremental classifier that learns from every packet seen.  
After 50 observations, it starts contributing to predictions.  
After 1,000 observations, it contributes up to 60% of the final decision.

**Why this matters:** If your network has unusual but legitimate traffic patterns, SentinelNet stops flagging them as attacks — it learned they're normal *for you*.

---

## Dashboard

The web dashboard updates every second via Server-Sent Events (SSE):

- **Live Traffic Chart** — normal vs. attack packets over time
- **Attack Type Breakdown** — donut chart of attack categories
- **Packet Feed** — real-time scrolling packet table with labels
- **Alert Timeline** — severity-coded alert history
- **Model Stats** — accuracy estimate and number of packets learned

---

## Project Structure

```
sentinelnet/
├── main.py              # Entry point & CLI
├── setup.py             # One-command setup
├── requirements.txt     # Dependencies
├── core/
│   ├── engine.py        # Main coordinator
│   ├── capture.py       # Scapy capture + demo simulator
│   ├── features.py      # Feature extraction (14 features)
│   ├── model.py         # Adaptive RF + SGD model
│   └── alert.py         # Alert manager & CSV logging
├── dashboard/
│   └── app.py           # Flask routes & SSE
├── templates/
│   └── index.html       # Dashboard UI
├── static/
│   ├── css/style.css    # Dark cybersecurity theme
│   └── js/dashboard.js  # Live charts & SSE client
├── models/              # Saved model state (auto-created)
└── logs/
    └── alerts.csv       # Alert log (auto-created)
```

---

## Dependencies

```
flask        — web dashboard
scapy        — packet capture
scikit-learn — Random Forest + SGD classifier
numpy        — numerical features
joblib       — model persistence
```

---

## Notes

- **Live mode requires root** (`sudo`) because raw packet capture needs OS-level permissions
- **macOS users:** You may need to grant Terminal full disk access in System Preferences
- The model is saved in `models/sentinel_model.pkl` — delete it or use `--reset-model` to start fresh
- Alerts are appended to `logs/alerts.csv` and never overwritten

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

Made with ♥ by [Merve Sude Boler](https://github.com/mervesudeboler)
