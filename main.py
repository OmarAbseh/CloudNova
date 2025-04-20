from detectors.config_checker import check_config_file

if __name__ == "__main__":
    filepath = "samples/config_example.yaml"
    results = check_config_file(filepath)

    print("THREAT DETECTION REPORT:")
    for r in results:
        print("-", r)
