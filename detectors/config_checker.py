import yaml

def check_config_file(filepath):
    threats = []

    try:
        with open(filepath, 'r') as file:
            data = yaml.safe_load(file)

        # Rule 1: flag if access_control.public is True
        if data.get("access_control", {}).get("public", False) is True:
            threats.append({
                "threat": "⚠️ Public access is enabled (access_control.public = true)",
                "severity": "High",
                "type": "Access Misconfiguration",
                "fix": "Set access_control.public to false or restrict access by role.",
                })
        # Rule 2: flag if password_required is False or missing
        if data.get("authentication", {}).get("password_required", True) is False:
            threats.append({
                "threat": "⚠️ Password authentication is disabled (authentication.password_required = false)",
                "severity": "Medium",
                "type": "Authentication Weakness",
                "fix": "Enable password_required = true to enforce credential validation."
                })

    except Exception as e:
        threats.append(f"Error reading file: {e}")

    return threats

