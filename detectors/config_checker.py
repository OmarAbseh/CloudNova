import yaml

def check_config_file(filepath):
    threats = []

    try:
        with open(filepath, 'r') as file:
            data = yaml.safe_load(file)

        # Rule 1: flag if access_control.public is True
        if data.get("access_control", {}).get("public", False) is True:
            threats.append("⚠️ Public access is enabled (access_control.public = true)")
        # Rule 2: flag if password_required is False or missing
        if data.get("authentication", {}).get("password_required", True) is False:
            threats.append("⚠️ Password authentication is disabled (authentication.password_required = false)")

    except Exception as e:
        threats.append(f"Error reading file: {e}")

    return threats

