# 🛡️ Report Notes – AI Threat Detection System
**Author:** Absa Omar Naser Adel  
**Started:** April 20, 2025  
**Repository:** [GitHub](https://github.com/OmarAbseh/Threat-detector)

---

##  1. Project Setup
- Set up folder from template ZIP
- Installed dependencies with `pip install -r requirements.txt`
- Activated Python venv
- Confirmed base file structure
- Verified Flask entry page

---

##  2. Config Checker 
 ### Public Access Rule
 - File: `detectors/config_checker.py`
 - Added rule: detect `access_control.public = true`
 - Test file: `samples/config_example.yaml`
 - Result: Detected public access
 - Tested using `main.py`
 ### Password Authentication Rule
 - File: `detectors/config_checker.py`
 - Added rule: detect `authentication.password_required = false`
 - Test file: `samples/config_example.yaml`
 - Result: Detected missing password requirement
 - Verified detection with `main.py`

## 3. Log Analyzer
 ### SSH Brute Force Rule
 - File: `detectors/log_analyzer.py`
 - Rule: Detects any log line containing "Failed password"
 - Test file: `samples/example_syslog.log`
 - Result: Detected brute force login attempt
 - Verified detection with `main.py`

## 4. Cloud Rules
 ### Public S3 Bucket Detection
 - File: `detectors/cloud_rules.py`
 - Rule: Detects S3 bucket names with "public"
 - Test file: `samples/sample_cludtrail.json`
 - Result: Detected public accesss to S3
 - Verified detection with `main.py`


 ## 5. Flask Dashboard Integration
 ### Upload and Scan Interface
 - File: `app.py`, `templates/index.html`
 - Feature: Upload files, select file type (config/log/cloud), click scan 
 - Output: Threats listed under the form after scanning
 - Result: Confirmed working Flash web interface with real-time scanning
 - Verified detection with `app.py`
 