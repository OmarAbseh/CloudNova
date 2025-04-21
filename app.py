from flask import Flask, request, render_template
from detectors.config_checker import check_config_file
from detectors.log_analyzer import analyze_log_file
from detectors.cloud_rules import analyze_cloudtrail_log
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    threats = []
    if request.method == "POST":
        file = request.files["file"]
        filetype = request.form["filetype"]
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)


        if filetype == "config":
            threats = check_config_file(filepath)
        elif filetype == "log":
            threats = analyze_log_file(filepath)
        elif filetype == "cloud":
            threats = analyze_cloudtrail_log(filepath)

    
    return render_template("index.html", threats=threats)


if __name__ == "__main__":
    app.run(debug=True)
    