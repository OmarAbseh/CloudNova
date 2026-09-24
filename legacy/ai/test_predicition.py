from predict import predict_threat_risk


example = {
    "public_access": 1,
    "password_required": 0,
    "timeout": 0,
    "failed_logins": 3,
    "duplicate_ip": 1

}

label, prob = predict_threat_risk(example)
print(f"Predicted Threat: {label} (Risk Score: {prob})")