from detectors.config_checker import check_config_file
from detectors.log_analyzer import analyze_log_file
from detectors.cloud_rules import analyze_cloudtrail_log

if __name__ == "__main__":
    print("THREAT DETECTION REPORT:")

    print("\n--- Config File ---")
    config_results = check_config_file("samples/config_example.yaml")
    for r in config_results:
        print("-", r)

    print("\n--- Log File ---")
    log_results = analyze_log_file("samples/example_syslog.log")
    for r in log_results:
        print("-", r)

    print("\n--- Cloud Log ---")
    cloud_results = analyze_cloudtrail_log("samples/sample_cloudtrail.json")
    for r in cloud_results:
        print("-", r)
            