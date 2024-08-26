import pandas as pd
from sklearn.ensemble import IsolationForest
import json

def load_logs(log_file_path):
    """Load logs from a JSON file."""
    with open(log_file_path, 'r') as file:
        logs = json.load(file)
    return logs

def preprocess_logs(logs):
    """Preprocess logs for analysis."""
    df = pd.DataFrame(logs)
    
    # Feature engineering: Convert FailureReason to numerical format
    df['FailureReason_encoded'] = df['FailureReason'].apply(lambda x: 1 if x == 'WrongPassword' else 0)
    
    # Selecting features for the model
    features = df[['LogonType', 'FailureReason_encoded']]
    return df, features

def detect_failed_logins(features):
    """Detect failed login attempts using Isolation Forest."""
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(features)
    
    # Predict anomalies
    predictions = model.predict(features)
    return predictions

def analyze_logs(log_file_path):
    """Main function to analyze logs and detect anomalies."""
    logs = load_logs(log_file_path)
    df, features = preprocess_logs(logs)
    
    # Detect anomalies
    df['Anomaly'] = detect_failed_logins(features)
    
    # Filter anomalies
    anomalies = df[df['Anomaly'] == -1]
    
    if not anomalies.empty:
        return {
            "status": "Anomalies Detected",
            "anomaly_count": len(anomalies),
            "details": anomalies.to_dict(orient="records")
        }
    else:
        return {
            "status": "No Anomalies Detected"
        }

if __name__ == "__main__":
    # Example usage
    log_file_path = "../logs/sample_logs.json"  # Update with the correct path
    result = analyze_logs(log_file_path)
    print(json.dumps(result, indent=4))
