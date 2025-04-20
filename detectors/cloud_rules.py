import json

def analyze_cloudtrail_log(filepath):
    threats = []

    try:
        with open(filepath, 'r') as file:
            data = json.load(file)

        # Rule 1: Detect public S3 access
        if data.get("eventName") == "PutObject":
            bucket = data.get("bucket", "").lower()
            if "public" in bucket:
                threats.append(f"⚠️ Public S3 access detected on bucket: {bucket}")

        # Rule 2: Detect overly permissive IAM policy (simulated)
        if "iam:PutRolePolicy" in data.get("eventName", ""):
            if "Action" in data and data["Action"] == "*":
                threats.append("⚠️ IAM policy grants full admin rights (Action: '*')")

    except Exception as e:
        threats.append(f"Error reading cloud log: {e}")

    return threats
