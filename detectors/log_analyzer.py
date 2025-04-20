def analyze_log_file(filepath):
    threats = []

    try:
        with open(filepath, 'r') as file:
            lines = file.readlines()

        for line in lines:
            if "Failed password" in line:
                threats.append("⚠️ SSH brute-force attempt detected: " + line.strip())

    except Exception as e:
        threats.append(f"Error reading log file: {e}")

    return threats
