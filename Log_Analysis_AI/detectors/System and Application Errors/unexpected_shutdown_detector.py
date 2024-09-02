import pandas as pd
from sklearn.ensemble import IsolationForest
import json

class UnexpectedShutdownDetector:
    def __init__(self, threshold=0.1):
        # Initialize the Isolation Forest model
        self.model = IsolationForest(contamination=threshold)
    
    def preprocess_logs(self, log_file):
        # Load the logs from a JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)
        
        # Filter for Event ID 6008 (Unexpected Shutdown)
        df = df[df['EventID'] == 6008]

        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Extract date and hour for feature engineering
        df['Date'] = df['Timestamp'].dt.date
        df['Hour'] = df['Timestamp'].dt.hour

        # Feature engineering: count occurrences per date
        df_counts = df.groupby(['Date']).size().reset_index(name='Count')
        
        return df_counts

    def train_model(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of unexpected shutdowns per day
        X = df[['Count']].values
        
        # Train the model
        self.model.fit(X)

    def detect_anomalies(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of unexpected shutdowns per day
        X = df[['Count']].values
        
        # Predict anomalies
        df['Anomaly'] = self.model.predict(X)
        df['Anomaly'] = df['Anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        # Filter anomalies
        anomalies = df[df['Anomaly'] == 'Anomaly']
        return anomalies

if __name__ == "__main__":
    detector = UnexpectedShutdownDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Train the model
    detector.train_model(log_file)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(log_file)
    
    if not anomalies.empty:
        print("Unexpected System Shutdowns Detected:")
        print(anomalies)
    else:
        print("No unexpected system shutdowns detected.")
