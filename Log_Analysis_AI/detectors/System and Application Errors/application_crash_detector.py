import pandas as pd
from sklearn.ensemble import IsolationForest
import json
from datetime import datetime

class ApplicationCrashDetector:
    def __init__(self, threshold=0.1):
        # Initialize the model with contamination parameter
        self.model = IsolationForest(contamination=threshold)
    
    def preprocess_logs(self, log_file):
        # Load logs from JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to DataFrame
        df = pd.DataFrame(logs)
        
        # Filter for Event ID 1000 (Application Error) and Event ID 1001 (Windows Error Reporting)
        df = df[df['EventID'].isin([1000, 1001])]

        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Feature engineering: count occurrences per application per day
        df['Date'] = df['Timestamp'].dt.date
        df = df.groupby(['AccountName', 'Date']).size().reset_index(name='Count')

        return df

    def train_model(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of application crashes per day
        X = df[['Count']].values
        
        # Train the model
        self.model.fit(X)

    def detect_anomalies(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of application crashes per day
        X = df[['Count']].values
        
        # Predict anomalies
        df['Anomaly'] = self.model.predict(X)
        df['Anomaly'] = df['Anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        # Filter anomalies
        anomalies = df[df['Anomaly'] == 'Anomaly']
        return anomalies

if __name__ == "__main__":
    detector = ApplicationCrashDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Train the model
    detector.train_model(log_file)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(log_file)
    
    if not anomalies.empty:
        print("High Frequency of Application Crashes Detected:")
        print(anomalies)
    else:
        print("No high frequency of application crashes detected.")
