import json
import pandas as pd
from sklearn.ensemble import IsolationForest

class SuspiciousPowerShellCommandDetector:
    def __init__(self, threshold=0.1):
        # Initialize the model
        self.model = IsolationForest(contamination=threshold)
        # Define a list of suspicious keywords or patterns (customize as needed)
        self.suspicious_patterns = [
            "Invoke-WebRequest",
            "IEX",
            "Invoke-Expression",
            "DownloadFile",
            "EncodedCommand",
            "New-Object System.Net.WebClient"
        ]

    def preprocess_logs(self, log_file):
        # Load the logs from a JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)
        
        # Filter for Event ID 4104 (PowerShell Script Block Logging)
        df = df[df['EventID'] == 4104]

        # Extract PowerShell command details
        df['Command'] = df['ScriptBlockText'].str.lower()

        # Create a feature column for suspicious command counts
        df['SuspiciousCount'] = df['Command'].apply(lambda cmd: sum(pattern in cmd for pattern in self.suspicious_patterns))

        return df

    def train_model(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of suspicious patterns in commands
        X = df[['SuspiciousCount']].values
        
        # Train the model
        self.model.fit(X)

    def detect_anomalies(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of suspicious patterns in commands
        X = df[['SuspiciousCount']].values
        
        # Predict anomalies
        df['Anomaly'] = self.model.predict(X)
        df['Anomaly'] = df['Anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        # Filter anomalies
        anomalies = df[df['Anomaly'] == 'Anomaly']
        return anomalies

if __name__ == "__main__":
    detector = SuspiciousPowerShellCommandDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Train the model
    detector.train_model(log_file)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(log_file)
    
    if not anomalies.empty:
        print("Suspicious PowerShell Commands Detected:")
        print(anomalies)
    else:
        print("No suspicious PowerShell commands detected.")
