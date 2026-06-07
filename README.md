# 🛡️ USBSentry-Core

<div align="center">

### Zero-Trust USB Security & Digital Forensics Framework

**A Real-Time USB Threat Detection, Device Access Control, and Forensic Analysis System**


</div>

---

## 📖 Overview

USBSentry-Core is an advanced endpoint security framework designed to defend systems against USB-borne malware, unauthorized data exfiltration, and removable media threats.

The platform follows a **Zero-Trust Security Model**, treating every newly connected USB storage device as potentially hostile until it has been thoroughly analyzed and verified.

Upon device insertion, USBSentry-Core automatically intercepts the device, performs forensic analysis, evaluates threat indicators, generates a security risk score, and records all findings in a persistent audit database.

By combining real-time monitoring, forensic intelligence, malware signature detection, and security analytics, the system provides an effective defense layer against one of the most common attack vectors in modern computing environments.

---

# 🎯 Objectives

* Prevent malware infiltration through USB devices.
* Detect suspicious files before execution.
* Provide automated forensic analysis.
* Generate actionable security recommendations.
* Maintain comprehensive audit trails.
* Support incident response investigations.

---

# 🚀 Key Features

## 🔒 Zero-Trust USB Access Control

* Real-time USB device detection.
* Automatic device interception.
* Pre-access security verification.
* Controlled access workflow.
* Threat-based decision making.

---

## 🧠 USBSentryBrain Forensic Engine

The custom forensic intelligence engine performs:

### File Analysis

* File enumeration
* Metadata inspection
* Hidden file detection
* Executable discovery

### Threat Detection

* Extension spoofing detection
* Suspicious script identification
* Malware signature matching
* Risk indicator extraction

### Security Scoring

* Multi-layer threat scoring
* Device risk classification
* Automated forensic recommendations

---

## 📊 Security Analytics Dashboard

The graphical management dashboard provides:

* Real-time monitoring
* Threat statistics
* Risk distribution analytics
* Device activity tracking
* Security recommendations
* System status visualization

Built using:

* Tkinter
* ttkbootstrap
* Python Visualization Components

---

## 📝 Audit Logging System

Every security event is stored for future investigation.

### Logged Information

* Device details
* Detection timestamps
* Threat scores
* Analysis results
* Security decisions
* Incident history

Benefits:

* Digital forensic investigations
* Compliance support
* Security auditing
* Incident response

---

## 🛡️ Threat Detection Capabilities

| Detection Module             | Description                             |
| ---------------------------- | --------------------------------------- |
| Extension Spoofing Detection | Identifies fake file extensions         |
| Hidden File Analysis         | Detects concealed files                 |
| Executable Discovery         | Finds suspicious executables            |
| Script Inspection            | Scans BAT, CMD, VBS, PowerShell scripts |
| Malware Signature Matching   | Compares files against known signatures |
| Threat Scoring Engine        | Calculates device risk levels           |
| Forensic Metadata Collection | Extracts investigative evidence         |

---

# 🏗️ System Workflow

```text
USB Device Connected
          │
          ▼
Device Interceptor
          │
          ▼
USBSentryBrain Analysis
          │
          ▼
Threat Evaluation
          │
     ┌────┴────┐
     ▼         ▼
   Safe    Suspicious
     │         │
     ▼         ▼
 Access    Quarantine
 Allowed    + Alert
          │
          ▼
 Audit Logging
```

---

# 📂 Project Structure

```bash
USBSentry-Core/
│
├── src/
│   ├── brain.py
│   ├── database.py
│   ├── gui.py
│   ├── interceptor.py
│   ├── log_viewer.py
│   └── logo.png
│
├── signatures.json
├── README.md
└── .gitignore
```

---

# ⚙️ Core Components

| File              | Purpose                                 |
| ----------------- | --------------------------------------- |
| `brain.py`        | USBSentryBrain forensic analysis engine |
| `interceptor.py`  | USB detection and interception module   |
| `database.py`     | SQLite database management              |
| `gui.py`          | Security dashboard interface            |
| `log_viewer.py`   | Historical log viewer                   |
| `signatures.json` | Malware signature repository            |

---

# 💻 Technology Stack

## Programming Language

* Python 3.x

## Security Components

* WMI (Windows Management Instrumentation)
* Signature-Based Detection
* Threat Scoring Engine
* Forensic Analysis Engine

## Database

* SQLite3

## User Interface

* Tkinter
* ttkbootstrap

## Data Handling

* JSON
* Threading
* Event Monitoring

---

# 🔍 Security Analysis Process

1. USB device insertion detected.
2. Device information collected.
3. File system scanned.
4. Threat indicators extracted.
5. Malware signatures checked.
6. Risk score generated.
7. Security recommendation produced.
8. Event stored in database.
9. Dashboard updated in real time.

---

# 📈 Example Risk Classification

| Risk Score | Classification  |
| ---------- | --------------- |
| 0 – 30     | Low Risk        |
| 31 – 60    | Medium Risk     |
| 61 – 100   | High Risk       |
| 100+       | Critical Threat |

---

# 🎓 Academic Significance

This project demonstrates practical implementation of:

* Digital Forensics
* Endpoint Security
* Cyber Threat Detection
* Secure Software Development
* Incident Response Automation
* Security Analytics
* USB Access Control Systems

---

# 🔮 Future Enhancements

## Security

* YARA Rule Integration
* Behavioral Malware Detection
* Machine Learning Threat Analysis
* Device Whitelisting
* Device Blacklisting

## Intelligence

* VirusTotal API Integration
* Threat Intelligence Feeds
* IOC Matching

## Reporting

* PDF Report Generation
* Automated Incident Reports
* Forensic Evidence Export

## Enterprise Features

* Multi-User Access Control
* Cloud Synchronization
* Centralized Security Monitoring

---


### Threat Analytics

```markdown
Add analytics screenshot here

/assets/analytics.png
```

### Log Viewer

```markdown
Add log viewer screenshot here

/assets/log_viewer.png
```

---



# 📜 License

This project is developed for educational, research, and demonstration purposes.

---

# ⭐ Project Vision

USBSentry-Core aims to transform traditional USB monitoring into an intelligent, forensic-driven security platform capable of detecting, analyzing, and responding to removable media threats before they compromise system integrity.

By integrating access control, forensic intelligence, threat analytics, and audit logging into a unified solution, the project provides a practical demonstration of modern endpoint security principles and Zero-Trust architecture.
