import pandas as pd
from sklearn.ensemble import IsolationForest
import json

class ServiceFailureDetector:
    def __init__(self, threshold=0.1):
        # Initialize the model
        self.model = IsolationForest(contamination=threshold)
    
    def preprocess_logs(self, log_file):
        # Load the logs from a JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)
        
        # Filter for Service Control Manager events (Event ID 7031 and 7034)
        df = df[df['EventID'].isin([7031, 7034])]
        
        # Extract relevant columns
        df = df[['EventID', 'ServiceName', 'Timestamp']]
        
        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Count failures per service
        df['Date'] = df['Timestamp'].dt.date
        df = df.groupby(['ServiceName', 'Date']).size().reset_index(name='FailureCount')
        
        return df

    def train_model(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of failures per day
        X = df[['FailureCount']].values
        
        # Train the model
        self.model.fit(X)

    def detect_anomalies(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # Feature: Count of failures per day
        X = df[['FailureCount']].values
        
        # Predict anomalies
        df['Anomaly'] = self.model.predict(X)
        df['Anomaly'] = df['Anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        # Filter anomalies
        anomalies = df[df['Anomaly'] == 'Anomaly']
        return anomalies

if __name__ == "__main__":
    detector = ServiceFailureDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Train the model
    detector.train_model(log_file)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(log_file)
    
    if not anomalies.empty:
        print("Service Failures Detected:")
        print(anomalies)
    else:
        print("No service failures detected.")
