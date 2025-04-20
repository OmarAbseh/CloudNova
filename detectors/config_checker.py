import yaml

def check_config_file(filepath):
    threats = []

    try:
        with open(filepath, 'r') as file:
            data = yaml.safe_load(file)

        # Simple rule: flag if access_control.public is True
        if data.get("access_control", {}).get("public", False) is True:
            threats.append("⚠️ Public access is enabled (access_control.public = true)")

    except Exception as e:
        threats.append(f"Error reading file: {e}")

    return threats
