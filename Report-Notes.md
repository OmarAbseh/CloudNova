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

 ## Phase 2 - Enchancements
 ### 1. Threat Metadata Added
 - File: `detectors/config_checker.py`, `detectors/log_analyzer.py`, `detectors/cloud_rules.py`
 - Upgrade: Changed output from plain strings to structured dicts with:
        -`threat`, `severity`, `type`, `fix`
 - Purpose: To better represent threats during development and display clean data
 - Result: Unifed output format across all detection engines.
 - Verified and tested in `main.py`

 
 ### 2. Log Analyzer Upgrade
 - File: `detectors/log_analyzer.py`
 - Rule: Detect repeated SSH login failures using log line analysis
 - Threat Type: Log-Based intrusion
 - Severity: Medium
 - Fix: Suggest monitoring brute-force activity or restricting SSH access
 - Test File: `samples/example_syslog.py`

 ### 3. Cloud Rules - Metadata + IAM Rule
 - File: `detectors/cloud_rules.py`
 - Public S3 Rule:
              - Detects bucket names with "public"
              - Type: Cloud Misconfiguration
              - Severity : High
              - Fix : Restrict or block access via S3 policy 
-IAM Rule:
              - Detects `Action: "*"` in IAM policy via mock CloudTrail log
              - Type: Cloud privilege Escalation
              - Severity: Critical
              - Fix: Limit IAM policy actions to required permissions only
              - Test File: `samples/sample_cloudtrail.json`

### 4. `main.py` Printer Upgrade
- Modified `main.py` to print metadata field: `threat`, `type`, `severity`, and `fix`
- Verified that all engines return results in consistent structure