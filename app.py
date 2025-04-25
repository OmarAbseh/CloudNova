from flask import Flask, request, render_template, render_template_string, jsonify, make_response
from detectors.config_checker import check_config_file
from detectors.log_analyzer import analyze_log_file
from detectors.cloud_rules import analyze_cloudtrail_log
from ai.predict import predict_threat_risk
from dotenv import load_dotenv
from datetime import datetime
from base64 import b64decode, b64encode
import openai
import yaml
import json
import os
import io

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/download-config", methods=["POST"])
def download_config_yaml():

    encoded = request.form.get("yaml")
    if not encoded:
        return "No config provided", 400
    

    try:
        decoded = b64decode(encoded).decode("utf-8")
    except Exception as e:
        return f"Error decoding YAML: {str(e)}", 400
    
    buffer = io.BytesIO()
    buffer.write(decoded.encode("utf-8"))
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Disposition"] = f"attachment; filename=config_{datetime.now().strftime('%Y%m%d')}.yaml"
    response.headers["Content-Type"] = "text/yaml"
    return response




@app.route("/cloudmind", methods=["GET", "POST"])
def cloudmind():
    if request.method == "POST":
        services = request.form.getlist("services")
        roles_input = request.form.get("roles", "")
        description = request.form.get("description", "")

    
        roles = {}
        for pair in roles_input.split(","):
            if ":" in pair:
                k, v = pair.strip().split(":")
                roles[k.strip()] = v.strip()
    
# Config Output

        config = {
        "description": description,
        "services": {},
        "roles": roles
        }


        for s in services:
            if s == "S3":
                config["services"]["S3"] = {
                    "public_access": False,
                    "encryption": "AES256",
                    "access_control": roles
             }

            elif s == "EC2":
                config["services"]["EC2"] = {
                    "instance_type": "t3.micro",
                    "iam_roles": list(roles.keys()),
                    "ssh_access": "restricted"
             }

            elif s == "Lambda":
                config["services"]["Lambda"] = {
                    "runtime": "python3.11",
                    "timeout": 10,
                    "env_access": "scoped"
             }

 # Convert to YAML for display/download

        yaml_str = yaml.dump(config, sort_keys=False)
        encoded = b64encode(yaml_str.encode()).decode()


        return render_template("cloudmind.html", yaml=yaml_str, encoded=encoded, services=["EC2", "S3", "Lambda"])


    return render_template("cloudmind.html", yaml=None)


@app.route("/download", methods=["POST"])
def download_report():
    from datetime import datetime
    import io

    score = request.form.get("score")
    threats = request.form.get("threats")

    report = {
        "timestamp": datetime.now().isoformat(),
        "ai_score": score,
        "threats": json.loads(threats)
    }

    buffer = io.BytesIO()
    buffer.write(json.dumps(report, indent=2).encode('utf-8'))
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Disposition"] = "attachment; filename=threat_report.json"
    response.headers["Content-Type"] = "application/json"
    return response

@app.route("/download-pdf", methods=["POST"])
def download_pdf_report():
    from datetime import datetime
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    score = request.form.get("score")
    threats = request.form.get("threats")

    if threats is None:
        return "No Threats submitted, Run a scan first.", 400
    
    threats = json.loads(threats)

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter


    y = height - 40
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "AI Threat Detection Report")
    y -= 30


    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"Generated: {datetime.now().strftime('%y-%m-%d %H:%M:%S')}")
    y -= 20
    pdf.drawString(50, y, f"AI Risk Score: {score}")
    y -= 30

    for i, threat in enumerate(threats, 1):
        if y < 100:
            pdf.showPage()
            y = height - 50
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, f"Threat {i}: {threat['threat']}")
        y -= 18
        pdf.setFont("Helvetica", 11)
        pdf.drawString(60, y, f"Type: {threat['type']}")
        y -= 16
        pdf.drawString(60, y, f"Severity: {threat['severity']}")
        y -= 16
        pdf.drawString(60, y, f"Fix: {threat['fix']}")
        y -= 30


    pdf.save()
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Disposition"] = "attachment; filename=threat_report.pdf"
    response.headers["Content-Type"] = "application/pdf"
    return response



@app.route("/ask", methods=["POST"])
def ask_assistant():
    question = request.json["question"].lower()

    if "public access" in question:
        answer = "Public access means a resource like an S3 bucket or system component is open to everyone on the internet. This is a high risk and should be avoided."
    elif "password required" in question or "authentication" in question:
        answer = "Password authentication ensures only valid users can log in. If it's disabled, anyone could try to access the system without validation."
    elif "iam" in question or "permission" in question:
        answer = "IAM policies define who can do what in your cloud environment. If an IAM policy uses 'Action: *', it gives full admin rights — a critical security flaw."
    elif "risk score" in question or "ai score" in question:
        answer = "The AI risk score is a prediction of how vulnerable your project setup is. A score of 1.0 = high threat; 0.0 = safe."
    elif "fix" in question:
        answer = "Every threat has a 'fix' section in your scan results. Follow those suggestions to secure your environment."
    elif "what can you do" in question or "who are you" in question:
        answer = "I'm your embedded security assistant. I explain threats, help you understand your scan results, and guide you toward more secure configurations."
    elif "download report" in question:
        answer = "The downloadable report feature (PDF/JSON) will allow you to archive your scan results and share them with a security team."
    elif "cloud mind" in question:
        answer = "Cloud Mind is an upcoming module that will generate secure IAM and cloud configuration files based on your inputs."
    elif "how does this work" in question:
        answer = "You upload your dev files (config, logs, cloud data), and we scan for threats using rules and AI. Threats are categorized, scored, and explained."
    else:
        answer = "I'm not sure how to answer that yet, but I'm learning more every day. Try asking about threats, scores, fixes, or how the system works."

    return jsonify({"answer": answer})


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        for filename in os.listdir(UPLOAD_FOLDER):
            os.remove(os.path.join(UPLOAD_FOLDER, filename))
        show_results = True
        threats = []
        ai_score = None

        try:
            config_file = request.files["config_file"]
            log_file = request.files["log_file"]
            cloud_file = request.files["cloud_file"]
        except KeyError:
            return render_template("index.html", threats=None, ai_score=None, show_results=False)

        config_path = os.path.join(UPLOAD_FOLDER, config_file.filename)
        log_path = os.path.join(UPLOAD_FOLDER, log_file.filename)
        cloud_path = os.path.join(UPLOAD_FOLDER, cloud_file.filename)

        config_file.save(config_path)
        log_file.save(log_path)
        cloud_file.save(cloud_path)

        threats += check_config_file(config_path)
        threats += analyze_log_file(log_path)
        threats += analyze_cloudtrail_log(cloud_path)

        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}

        public_access = int(config.get("access_control", {}).get("public", False))
        password_required = int(config.get("authentication", {}).get("password_required", True))
        timeout = int(config.get("session", {}).get("timeout", 10))

        failed_logins = 0
        ip_tracker = {}

        with open(log_path, "r") as log:
            for line in log:
                if "Failed password" in line:
                    failed_logins += 1
                    parts = line.split()
                    if "from" in parts:
                        idx = parts.index("from")
                        ip = parts[idx + 1] if idx + 1 < len(parts) else None
                        if ip:
                            ip_tracker[ip] = ip_tracker.get(ip, 0) + 1

        duplicate_ip = int(any(count > 1 for count in ip_tracker.values()))

        with open(cloud_path, "r") as cloud_file:
            try:
                cloud_data = json.load(cloud_file)
                cloud_permission_risk = int(cloud_data.get("Action", "") == "*")
            except Exception:
                cloud_permission_risk = 0

        features = {
            "public_access": public_access,
            "password_required": password_required,
            "timeout": timeout,
            "failed_logins": failed_logins,
            "duplicate_ip": duplicate_ip,
            "cloud_permission_risk": cloud_permission_risk
        }

        print("AI Features Submitted:", features)
        _, ai_score = predict_threat_risk(features)
        return render_template("index.html", threats=threats, ai_score=ai_score, show_results=True)

    # Initial page load (GET)
    return render_template("index.html", threats=None, ai_score=None, show_results=False)

if __name__ == "__main__":
    app.run(debug=True)
    