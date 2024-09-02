import pandas as pd
from sklearn.ensemble import IsolationForest
import json

class HighResourceUsageDetector:
    def __init__(self, threshold=0.1):
        # Initialize the Isolation Forest model with contamination threshold
        self.model = IsolationForest(contamination=threshold)
    
    def preprocess_logs(self, log_file):
        # Load the logs from a JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)

        # Filter for relevant event IDs (e.g., CPU, Memory, Disk usage)
        df = df[(df['EventID'].isin([3001, 3002, 3003]))]  # Example Event IDs for CPU, Memory, Disk usage

        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])

        # Extract features (e.g., CPU usage, Memory usage, Disk usage)
        features = df[['CPUUsage', 'MemoryUsage', 'DiskUsage']]
        
        return features

    def train_model(self, log_file):
        features = self.preprocess_logs(log_file)

        # Train the Isolation Forest model
        self.model.fit(features)

    def detect_anomalies(self, log_file):
        features = self.preprocess_logs(log_file)

        # Predict anomalies
        features['Anomaly'] = self.model.predict(features)
        features['Anomaly'] = features['Anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        # Filter anomalies
        anomalies = features[features['Anomaly'] == 'Anomaly']
        return anomalies

if __name__ == "__main__":
    detector = HighResourceUsageDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Train the model
    detector.train_model(log_file)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(log_file)
    
    if not anomalies.empty:
        print("High System Resource Usage Detected:")
        print(anomalies)
    else:
        print("No high system resource usage detected.")
