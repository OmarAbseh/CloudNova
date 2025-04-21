def analyze_log_file(filepath):
    threats = []

    try:
        with open(filepath, 'r') as file:
            lines = file.readlines()

        for line in lines:
            if "Failed password" in line:
                threats.append({
                    "threat": "Potential SSH brute-force login attempt",
                    "type": "Log-Based Intrusion",
                    "severity": "Medium",
                    "fix": "Monitor repeated failed login attempts and restrict SSH access if necessary.",
                    "line": line.strip()
                    })

    except Exception as e:
        threats.append({
            "threat": f"Error reading log file: {e}",
            "type": "System Error",
            "severity": "Low",
            "fix": "Check LOG formatting and file structure."
           })

    return threats
