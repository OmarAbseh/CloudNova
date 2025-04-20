from detectors.config_checker import check_config_file
from detectors.log_analyzer import analyze_log_file

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
