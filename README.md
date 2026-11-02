# 🛡️ Intelligent Campus Cyber Security Threat Detection System

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Supervised-orange.svg)](https://scikit-learn.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: Passing](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

> An enterprise-grade, supervised machine learning cyber defense and intrusion detection system engineered specifically for university and college campus network infrastructures.

---

## 📌 1. Project Overview

University campuses possess unique cybersecurity challenges: high-bandwidth residential dormitories, open academic research compute clusters, mission-critical administrative databases holding student financial and grade records, unauthenticated guest Wi-Fi networks, and public-facing student portals vulnerable to DDoS attacks during enrollment and exam periods.

This system monitors telemetry flows crossing campus subnets, extracts 49 domain-specific network features, classifies suspicious activities using supervised machine learning algorithms, and triggers automated containment playbooks (firewall rules, 802.1X VLAN quarantine, rate-limiting).

---

## 🏛️ 2. Campus Network Topology & Monitored Subnets

```
                  ┌─────────────────────────────────────┐
                  │       External Internet (WAN)       │
                  └──────────────────┬──────────────────┘
                                     │
                   [Core Campus Border Firewall / BGP]
                                     │
         ┌──────────────┬────────────┼────────────┬──────────────┐
         │              │            │            │              │
         ▼              ▼            ▼            ▼              ▼
   ┌───────────┐  ┌───────────┐┌───────────┐┌───────────┐  ┌───────────┐
   │10.10.0.0/16│  │10.20.0.0/16││10.30.0.0/16││10.40.0.0/16│  │10.50.0.0/16│
   │Student    │  │Computer   ││Admin &    ││University │  │Guest &    │
   │Dormitories│  │Science    ││Financial  ││Data Center│  │Visitor    │
   │Residential│  │Research   ││Records    ││LMS / Web  │  │Wi-Fi      │
   │Wi-Fi      │  │Labs       ││Database   ││Portals    │  │(Zero-Trust│
   └───────────┘  └───────────┘└───────────┘└───────────┘  └───────────┘
```

| Campus Subnet | CIDR Range | Risk Level | Common Threat Vectors |
| :--- | :--- | :--- | :--- |
| **Student Dormitories** | `10.10.0.0/16` | Medium | P2P torrents, crypto mining beacons, botnet participation, infected personal devices. |
| **CS & Research Labs** | `10.20.0.0/16` | High | SSH brute-force, internal port scans, compilation cluster misuse, unauthorized pivot attacks. |
| **Administration** | `10.30.0.0/16` | **Critical** | Confidential grade alteration, financial aid record exfiltration, credential stuffing. |
| **Data Center / Portals** | `10.40.0.0/16` | **Critical** | Volumetric SYN/UDP DDoS flood on LMS/Canvas during registration, Web SQLi & XSS. |
| **Guest Wi-Fi** | `10.50.0.0/16` | Medium | Unauthenticated rogue devices, ARP poisoning, cross-subnet traversal attempts. |

---

## 🎯 3. Threat Classification Taxonomy

The system performs multi-class supervised classification across 7 distinct network states:

1. **`Benign`**: Legitimate student/faculty browsing, video lectures, cloud storage, VoIP, academic downloads.
2. **`DDoS_Flood`**: High-packet-rate volumetric flood targeting university registration or LMS portals.
3. **`Brute_Force`**: Repeated dictionary and password guessing against SSH (port 22), FTP (port 21), or admin portals.
4. **`Port_Scan`**: Reconnaissance sweeps (SYN, FIN, Xmas) across campus subnets to discover vulnerable open ports.
5. **`Web_Attack`**: SQL Injection (`UNION SELECT`, `' OR 1=1`), XSS, and directory traversal targeting campus web apps.
6. **`Botnet_C2`**: Compromised lab workstations periodically communicating with external Command-and-Control servers.
7. **`Data_Exfiltration`**: Anomalous high-volume outbound data transfers from administrative database subnets to external IPs.

---

## 🔬 4. Machine Learning Pipeline & Benchmark

Five supervised machine learning architectures were trained and evaluated on stratified campus telemetry:

| Model Architecture | Accuracy | Precision (Macro) | Recall (Macro) | F1-Score (Macro) | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest Classifier** | **100.0%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 🏆 **Champion** |
| **Gradient Boosting (GBDT)** | **100.0%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Production |
| **Decision Tree (CART)** | **100.0%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Baseline |
| **MLP Neural Network** | **99.95%** | **0.9991** | **0.9998** | **0.9994** | **1.0000** | Production |
| **Logistic Regression** | **99.87%** | **0.9975** | **0.9996** | **0.9985** | **1.0000** | Baseline |

### Top 10 Discriminative Network Features (Random Forest Gini Importance)
1. `src_bytes`: Key separator for data exfiltration and payload volume anomalies.
2. `payload_entropy`: Detects encrypted/packed C2 beacons and SQL injection strings.
3. `syn_to_ack_ratio`: Classic signature for asymmetric SYN flooding attacks.
4. `syn_flag_count`: Indicates rapid connection attempts in scans and floods.
5. `dst_bytes`: Differentiates normal request-response dialogs from unanswered attacks.
6. `src_pkts`: Volumetric packet counts.
7. `failed_logins`: Primary signature for authentication brute force attacks.
8. `bytes_per_pkt`: Discriminates small probe packets from bulk data dumps.
9. `dst_pkts`: Response packet metrics.
10. `avg_pkt_size`: Flow packet dimension statistics.

---

## ⚡ 5. Interactive Security Operations Center (SOC) Dashboard

The system includes a modern, dark-themed SOC web interface:
- **Live Telemetry Stream**: Real-time simulated campus traffic with dynamic alert badges and latency metrics.
- **Interactive Custom Flow Predictor**: Test custom flows or load attack scenario presets (SYN Flood, SSH Brute Force, Web SQLi, Data Exfiltration).
- **Interactive Visual Charts**: Real-time Doughnut Threat Distribution and Bar Charts by Campus Subnet.
- **Automated Mitigation Advisory**: Generates copy-paste ready `iptables`, `Cisco IOS ACL`, and `ModSecurity` rules.
- **Campus Topology Viewer**: Overview of subnet risk scores and active containment tiers.

---

## 🚀 6. Quick Start Guide

### Step 1: Clone Repository
```bash
git clone https://github.com/<YOUR_USERNAME>/intelligent-campus-cyber-threat-detection.git
cd intelligent-campus-cyber-threat-detection
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the CLI Live Demo
```bash
python run_demo.py
# or double-click run_demo.bat (on Windows)
```

### Step 4: Launch the Web SOC Dashboard
```bash
python dashboard/app.py
# or double-click start_dashboard.bat (on Windows)
```
Open your browser at: **`http://127.0.0.1:8000`**

### Step 5: Run Automated Test Suite
```bash
pytest tests/ -v
```

---

## 💻 7. CLI Utilities

### Retrain Models
```bash
python models/train.py
```

### View Evaluation Benchmark Report
```bash
python models/evaluate.py
```

### Interactive Single Flow Predictor
```bash
python models/predict.py --interactive
```

### Simulate N Live Streaming Campus Flows
```bash
python models/predict.py --simulate 10
```

### Batch Classify a Network Log CSV File
```bash
python models/predict.py --file path/to/logs.csv --output results.csv
```

---

## 🔌 8. REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | SOC Dashboard Web Interface |
| `GET` | `/api/status` | Model and system health status |
| `GET` | `/api/metrics` | Model benchmark evaluation results & feature importance |
| `POST` | `/api/predict` | Classify a single flow payload |
| `POST` | `/api/batch-predict` | Upload a CSV file for batch threat detection |
| `GET` | `/api/simulate-stream` | Stream live simulated campus events with predictions |
| `GET` | `/api/mitigation/{threat}` | Retrieve automated firewall rules and mitigation playbooks |

---

## 📂 9. Project Directory Structure

```
intelligent-campus-cyber-threat-detection/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI automated pipeline
├── config/
│   └── config.yaml              # Subnets, features, and model configurations
├── dashboard/
│   ├── app.py                   # FastAPI application & REST API server
│   ├── static/
│   │   ├── css/style.css        # SOC Cyber Defense styling
│   │   └── js/dashboard.js      # Real-time charts & stream controller
│   └── templates/
│       └── index.html           # Modern responsive SOC web dashboard
├── data/
│   ├── raw/                     # Raw generated campus network traffic
│   ├── processed/               # Stratified train and test splits
│   └── generate_campus_dataset.py # CLI dataset generation script
├── models/
│   ├── saved/                   # Serialized model, scalers, and encoders
│   │   ├── best_model.joblib
│   │   ├── label_encoder.joblib
│   │   ├── scaler.joblib
│   │   ├── feature_columns.json
│   │   └── metrics_summary.json
│   ├── train.py                 # CLI model training pipeline runner
│   ├── evaluate.py              # CLI model evaluation benchmark report
│   └── predict.py               # CLI interactive and batch inference tool
├── notebooks/
│   └── campus_threat_detection_demo.ipynb # End-to-end interactive tutorial
├── src/
│   ├── __init__.py
│   ├── config_loader.py         # Configuration loader
│   ├── dataset_generator.py     # Realistic campus flow dataset generator
│   ├── detector.py              # Real-time inference engine
│   ├── evaluator.py             # Classification metric evaluator
│   ├── feature_engineering.py   # Domain network feature extraction
│   ├── incident_advisor.py      # MITRE ATT&CK mitigation playbook
│   ├── models.py                # Supervised ML model registry
│   ├── preprocessor.py          # Scaling and categorical encoding
│   └── train_pipeline.py        # Complete training orchestrator
├── tests/
│   ├── test_data.py             # Data generator unit tests
│   ├── test_preprocessor.py     # Preprocessing & engineering tests
│   └── test_detector.py         # Detector & mitigation advisory tests
├── .gitignore
├── LICENSE                      # MIT Open Source License
├── README.md                    # Project documentation
├── requirements.txt             # Python dependencies
├── run_demo.py                  # Live simulation demonstration
├── run_demo.bat                 # Windows one-click demo
├── run_training.bat             # Windows one-click training
├── setup.py                     # Python package installation configuration
└── start_dashboard.bat          # Windows one-click dashboard launcher
```

---

## 📜 10. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
