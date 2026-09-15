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
                threats.append({
                    "threat": f"Public S3 access detected on bucket: {bucket}",
                    "type": "Cloud Misconfiguration",
                    "severity": "High",
                    "fix": "Restrict the bucket policy or block all public access in S3 settings."
                    })
                
        # Rule 2: Detect overly permissive IAM policy (simulated)
        if "iam:PutRolePolicy" in data.get("eventName", ""):
            if "Action" in data and data["Action"] == "*":
                threats.append({
                    "threat": "IAM policy grants full administrative privileges (Action: '*')",
                    "type": "Cloud Privilege Escalation",
                    "severity": "Critical",
                    "fix": "Restrict the IAM policy actions to only what's necessary for the role."
                    })
                
    except Exception as e:
        threats.append({
            "threat": f"Error reading cloud log: {e}",
            "type": "System Error",
            "severity": "Low",
            "fix": "Check json formatting and file structure."
            
            })

    return threats
