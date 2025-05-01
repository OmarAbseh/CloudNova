# 🛡️ CloudNova - AI-Powered Cloud Threat Detection System

CloudNova is an advanced AI-driven threat detection system designed to identify misconfigurations, risky logs, and cloud-level security issues during cloud software development. Built for DevSecOps engineers, researchers, and cloud developers.

---

## 📌 Project Overview
- **Author**: Absa Omar Naser Adel
- **Thesis Project**: University of Debrecen
- **Start Date**: April 20, 2025
- **Repository**: [`CloudNova`](https://github.com/OmarAbseh/CloudNova/)

---

## ⚙️ Core Features

### ✅ Multi-Layer Detection
- **Config Checker**: Detects public access and insecure authentication rules in YAML configs
- **Log Analyzer**: Detects brute-force attacks, repeated SSH failures, and duplicate IPs
- **Cloud Rules**: Detects public S3 buckets and wildcard IAM permissions

### 📊 Flask Web Interface
- Upload config/log/cloud files and scan instantly
- Displays structured threat metadata (type, severity, fix)

### 🧠 AI Risk Assessment
- Predicts overall project risk using DecisionTreeClassifier (scikit-learn)
- Input features extracted from uploaded files
- Returns color-coded risk score + threat list

### 🤖 AI Assistant (Mock)
- Interactive threat explanation chatbot (Flask + JS frontend)
- Handles questions like "what is public access?" or "explain IAM risks"
- Ready for GPT-4 integration

### 📄 Report Downloads
- Download full threat report as `.json` or `.pdf`
- Includes risk score, threats, fixes, and project metadata

### 🧠 CloudMind Generator
- AI-powered secure config file generator
- Inputs: AWS services + roles + project description
- Output: Encrypted downloadable YAML (EC2, S3, Lambda supported)

---

## 🚀 Tech Stack

| Category       | Tools                        |
|----------------|------------------------------|
| Language       | Python 3.10+                 |
| Web Framework  | Flask + Bootstrap 5          |
| AI/ML          | Scikit-learn, JSON + CSV     |
| Parsing        | PyYAML, Log parsers, JSON    |
| UI Assistant   | JS (Fetch) + Flask Routes    |
| PDF Export     | ReportLab                    |
| File Upload    | Multipart/form POST          |

---

## 🧪 Detection Logic (Sample)

| Type            | Rule Detected                        | Severity  | Fix                                  |
|------------------|---------------------------------------|-----------|---------------------------------------|
| Config           | `access_control: public`             | High      | Restrict public access                |
| Config           | `password_required: false`           | High      | Enforce password authentication       |
| Log              | `Failed password` (SSH brute force)  | Medium    | Monitor + block suspicious IPs        |
| CloudTrail       | `Action: "*"` in IAM policy           | Critical  | Scope permissions to least privilege |

---

## 🧠 AI Model - Dataset Features

| Feature               | Source       |
|------------------------|--------------|
| public_access          | config.yaml  |
| password_required      | config.yaml  |
| timeout                | config.yaml  |
| failed_logins          | syslog.log   |
| duplicate_ip           | syslog.log   |
| cloud_permission_risk  | cloudtrail.json |

---

## 📁 Folder Structure

```bash
.
├── app.py                # Flask backend
├── templates/
│   ├── index.html        # Main dashboard UI
│   └── cloudmind.html    # Config generator UI
├── detectors/
│   ├── config_checker.py
│   ├── log_analyzer.py
│   └── cloud_rules.py
├── ai/
│   ├── threat_dataset.csv
│   ├── model.pkl
│   └── assistant_knowledge.json
├── samples/
│   ├── dev_config.yaml
│   ├── dev_log.log
│   └── dev_cloudtrail.json
```

---

## 🎓 Thesis Status (April 2025)
- ✅ Core system and AI modules built
- ✅ Flask frontend complete
- ✅ Assistant and CloudMind integrated
- 🔄 Final polishing and README screenshots pending

---

## 🧠 Future Upgrades
- GPT integration for AI Assistant
- Real AWS API scanning
- CI/CD integration for DevSecOps pipelines

---

## 📫 Contact

- 📧 omar_absah@icloud.com
- 💼 [LinkedIn: Omar Abseh](https://www.linkedin.com/in/omarabseh/)
- 🔗 GitHub: [OmarAbseh](https://github.com/OmarAbseh)

> "Secure DevOps isn't optional. It’s the foundation of resilient innovation."