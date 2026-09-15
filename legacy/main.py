from detectors.config_checker import check_config_file
from detectors.log_analyzer import analyze_log_file
from detectors.cloud_rules import analyze_cloudtrail_log

if __name__ == "__main__":
    print("THREAT DETECTION REPORT:")

    print("\n--- Config File ---")
    for r in check_config_file("samples/dev_config.yaml"):
        print(f"\nThreat: {r['threat']}")
        print(f"Type: {r['type']}")
        print(f"Severity: {r['severity']}")
        print(f"Fix: {r['fix']}")

    print("\n--- Log File ---")
    for r in analyze_log_file("samples/dev_log.log"):
        print(f"\nThreat: {r['threat']}")
        print(f"Type: {r['type']}")
        print(f"Severity: {r['severity']}")
        print(f"Fix: {r['fix']}")
        print(f"Line: {r['line']}")

    print("\n--- Cloud Log ---")
    for r in analyze_cloudtrail_log("samples/dev_cloudtrail.json"):
        print(f"\nThreat: {r['threat']}")
        print(f"Type: {r['type']}")
        print(f"Severity: {r['severity']}")
        print(f"Fix: {r['fix']}")
