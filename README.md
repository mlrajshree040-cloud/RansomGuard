# 🛡️ RansomGuard

## 🎯 Overview

**RansomGuard** is a multi-layered ransomware defense system that combines **deception technology**, **behavioral analysis**, **YARA signatures**, **machine learning**, and **automatic recovery** to protect your files from ransomware attacks.

The system detects, contains, and reverses ransomware attacks within **under 3 seconds** — with **zero data loss** — using a SHA-256 verified vault for automatic file restoration.

---

## ✨ Features

### 🍯 Deception Layer
- **30 Decoy Files** — Fake "valuable" documents placed in protected folders
- **4 Honeypot Shares** — Fake `IT_Backup`, `CEO_Documents`, `Confidential_HR`, `Customer_Database` folders
- **Any touch = high-confidence attack signal**

### 🧠 Detection Layer
- **7-Signal Scoring Engine** — Multiple independent detection signals
- **YARA Signature Engine** — 4 rule families (Generic, LockBit 3.0, WannaCry, LYNX)
- **ML Classifier** — Random Forest with 6 behavioral features
- **Entropy Analysis** — Detects encrypted content
- **Behavioral Analysis** — Mass file ops, renames, extension changes

### 🔄 Response Layer
- **Process Kill** — Terminates attacker processes
- **Quarantine System** — Isolates detected files with metadata
- **SHA-256 Vault** — Clean backups of every protected file
- **Auto-Rollback** — Restores files within 3 seconds
- **Decoy Regeneration** — Rebuilds traps after attack

### 🔒 Self-Defense
- **Watchdog Process** — Auto-respawn if killed
- **Integrity Monitor** — SHA-256 verification every 30 seconds
- **Signal Handler** — Catches SIGTERM/SIGBREAK
- **Tamper Audit Log** — Records every attack attempt

### 📸 Forensic Analysis
- **Screenshot Capture** — Auto-capture on attack detection
- **Sandbox Detonation** — Isolated behavior analysis
- **Full System Scanner** — Multi-threaded threat scan

### 🌐 Enterprise Dashboard
- **8-Section Console** — Overview, Events, Integrity, Threat, YARA, Defense, Screenshots, Sandbox
- **Real-time Updates** — 1-second refresh
- **Animated Background** — Particle network visualization
- **Professional UI** — Glassmorphism + smooth transitions

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- Windows, Linux, or macOS

### Installation


### Clone the repository

git clone https://github.com/mlrajshree040-cloud/RansomGuard.git

cd RansomGuard

### Install dependencies

pip install -r requirements.txt

### Run


python main.py

### Test an Attack (in a second terminal)


python simulate_attack.py





## 📁 Project Structure
```
RansomGuard/
│
├── ransomguard/
│   ├── config.py
│   ├── state.py
│   ├── logger.py
│   ├── entropy.py
│   ├── decoy_manager.py
│   ├── honeypot.py
│   ├── quarantine.py
│   ├── monitor.py
│   ├── detector.py
│   ├── response.py
│   ├── rollback.py
│   ├── scanner.py
│   ├── scanner_state.py
│   ├── selfdefense.py
│   ├── watchdog_process.py
│   ├── screenshot.py
│   ├── sandbox.py
│   ├── sandbox_state.py
│   ├── yara_engine.py
│   ├── yara_rules/
│   │   ├── ransomware_generic.yar
│   │   ├── lockbit.yar
│   │   ├── wannacry.yar
│   │   └── lynx.yar
│   ├── web_dashboard.py
│   └── dashboard.py
│
├── ml/
│   ├── feature_extractor.py
│   ├── ml_detector.py
│   ├── generate_dataset.py
│   └── train_model.py
│
├── protected_folder/
├── protected_folder_2/
├── protected_folder_3/
├── protected_folder_4/
├── protected_folder_5/
├── honeypot_shares/
├── quarantine/
├── screenshots/
├── sandbox/
├── vault/
│
├── main.py
├── simulate_attack.py
├── simulate_yara_attack.py
├── scan_main.py
├── requirements.txt
├── README.md
└── LICENSE


┌─────────────────────────────────────────────────────────┐
│                    ATTACK LIFECYCLE                      │
│                                                          │
│  1. 🍯 Decoys deployed in protected folders             │
│     ↓                                                    │
│  2. 🦠 Ransomware starts encrypting files               │
│     ↓                                                    │
│  3. 🎯 Attacker touches a decoy file                    │
│     ↓                                                    │
│  4. 🚨 Detection (7 signals scored)                     │
│     ↓                                                    │
│  5. 📸 Screenshot captured (forensic evidence)          │
│     ↓                                                    │
│  6. 🔪 Attacker process killed                          │
│     ↓                                                    │
│  7. 🗑️ Rogue files quarantined                          │
│     ↓                                                    │
│  8. 🔄 Files restored from SHA-256 vault                │
│     ↓                                                    │
│  9. 🍯 Decoys regenerated                               │
│     ↓                                                    │
│ 10. ✅ Dashboard shows CONTAINED — 0 data loss          │
│                                                          │
│     Time: Under 3 seconds                                │
└─────────────────────────────────────────────────────────┘

```



### 📊 Detection Signals
```
Signal	              Severity	        Confidence
Honeypot touched	      +200	         Absolute
Decoy touched	          +100           Very High
YARA signature match	   +80	         High
Ransomware extension	   +60	         High
ML classifier	           +50	         Medium-High
Mass file operations	   +40	         Medium
High entropy	           +30	         Low

```

### 🤖 Machine Learning

Features (6)

1. ops_per_sec — File operations per second

2. unique_exts — Distinct extensions touched

3. renames — Rename/move count

4. ext_changes — Extension changes

5. decoy_touches — Decoy file hits

6. avg_entropy — Average entropy of touched files

## Model

Algorithm: Random Forest (200 trees, max depth 12)

Accuracy: 99.75% (synthetic data)

ROC-AUC: 0.9998

Training data: 2,000 samples (1,000 benign, 1,000 ransomware)
```
Feature        Importance
Feature        Importance
ops_per_sec	    29.8%
renames	        24.1%
avg_entropy	    18.7%
ext_changes	    14.3%
decoy_touches	   9.8%
unique_exts	     3.3%
```
### 🛡️ YARA Rules
```
Family	       Coverage
Generic	        Ransom notes, CryptoAPI, shadow deletion, security tool kills
LockBit 3.0	    18 unique byte sequences from LockBit payload
WannaCry	      tasksche.exe, WNcry@2ol7, kill-switch domain
LYNX	          20 strings from DNSC public advisory
```

### 📄 License
MIT License — see LICENSE file for details.

You are free to use, modify, and distribute this software with attribution.
