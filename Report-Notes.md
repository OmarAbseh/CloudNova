# 🛡️ Report Notes – AI Threat Detection System
**Author:** Absa Omar Naser Adel  
**Started:** April 20, 2025  
**Repository:** [GitHub](https://github.com/OmarAbseh/Threat-detector)

---

##  Phase 1 - Project Setup
 - Set up folder from template ZIP
 - Installed dependencies with `pip install -r requirements.txt`
 - Activated Python venv
 - Confirmed base file structure
 - Verified Flask entry page

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
 - Result: Confirmed working Flask web interface with real-time scanning
 - Verified detection with `app.py`

## Phase 2 - Enhancements
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

 ### 5. Full System Stability with Realistic Dev Files
 - Files: `samples/dev_config.yaml`, `dev_log.log`, `dev_cloudtrail.json`
 - Purpose: Simulate real-world dev-stage inputs during software project development
 - Fixes Applied:
              - Added defensive parsing to `config_checker.py` using `safe_load(file) or {}`
              - Fixed incorrect cloud rule key (`eventName2 → eventName`)
              - Standardized all `except` blocks to return structured threat objects
 - Result: System now returns clean structured metadata across all three modules (config, log, cloud)
 - Test: `main.py` verified detection for all inputs with expected results

 ### 6. Flask UI Upgrade - Threat Metadata Display
 - File: `templates/index.html`
 - Upgrade: Web interface now displays:
              - Threat message
              - Type
              - Severity (color-coded)
              - Fix recommendation
 - Result: Improved readability and professionalism
 - Verified by uploading dev-stage files via dashboard

 
 


## Phase 3 – AI Integration

 ### 1. Define AI Use Case
 - Goal: Predict whether a dev environment is secure or risky based on config/log/cloud features
 - Input sources: 
              - YAML (config)
              - Syslog (SSH brute force)
              - CloudTrail JSON (IAM over-permission)

 ### 2. Dataset Creation
 - File: `ai/threat_dataset.csv`
 - Columns: public_access, password_required, timeout, failed_logins, duplicate_ip, cloud_permission_risk, threat
 - Labels: 1 = risky project, 0 = safe
 - Added new cases for better model generalization

 ### 3. Model Training
 - Model: DecisionTreeClassifier (scikit-learn)
 - Evaluation:
              - Accuracy: 1.0
              - Precision: 1.0
              - Recall: 1.0
 - Saved to: `ai/model.pkl`

 ### 4. Feature Extraction
 - Extracted real values from all 3 files:
 - Config: access_control, authentication, session
 - Log: failed SSH attempts, duplicate IPs
 - Cloud: Action = "*" check

 ### 5. Flask Integration
 - Full POST upload handler with cleanup
 - Features passed to AI model and prediction displayed
 - AI Risk Score shown in dashboard with color-coded threats
 - Print debug used for transparency




## Phase 4 - Final Polish & AI Assistant

 ### Step 1: UI Redesign
 - File: `templates/index.html`
 - Libraries: Integrated Bootstrap 5 (CDN)
 - Layout:
              - Centered title
              - Modern upload form (Config, Log, Cloud)
              - Full-width Bootstrap button
              - AI Risk Score shown in alert box
              - Detected threats displayed in cards (with color-coded severity)
 - Status: Fully integrated and tested
 - Purpose: Enhance visual professionalism and structure system for future modules
   
 ### Step 2: AU Assistant Panel (Mock might add gpt later)
 - Files: `index.html`, `app.py`
 - Description: Added a local simulated assistant for threat clarification and AI interaction
 - Frontend: Bootstrap UI with input field and result box
 - Backend: Flask `/ask` route with keyword-based mock logic
 - Capabilities:
              - Explains public access, password auth, IAM, scoring
              - Responds to “who are you”, “how does this work?”, and “cloud mind”
 - Status: Tested and working
 - Note: Fully upgradeable to GPT later
 
 ### Step 3: Flask Assistant Logic
  - Files: `App.py`
  - Route: `/ask` POST
  - Logic: interprets user question → return JSON with helpful explanation
  - Handles: Public access, IAM, passwords, risk score, system purpose, etc..
  - Smart fallback response if no matches found

 ### Step 4: JS Integration
  - Files: `index.html`
  - Script: `fetch("/ask)` call using Bootstrap UI
  - Output: Appends answer below input box
  - Status: Fully tested

  ### Step 5: Assistant Mock Intelligence
  - Smart keyword-matching logic
  - Ready for GPT upgrade (Logic in previous commits, .env file ready)
  