import joblib
import pandas as pd

def predict_threat_risk(config):
    """
    input: config = {
    "public_access": 1,
    "password_required": 0,
    "timeout": 0,
    "failed_logins": 3,
    "duplicate_ip":1
    
    }
    Output: prediction (0 or 1), probability (float)
    
    """

    model = joblib.load("ai/model.pkl")
    df = pd.DataFrame([config])
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1] # probability of class 1
    return prediction, round(probability, 2)