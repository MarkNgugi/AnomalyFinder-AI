import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import json

class FrequentRebootDetector:
    def __init__(self, time_window_hours=24, threshold=0.1):
        """
        Initialize the FrequentRebootDetector.
        
        Parameters:
        - time_window_hours: Time window (in hours) to look for frequent reboots.
        - threshold: Contamination threshold for the Isolation Forest algorithm.
        """
        self.time_window = timedelta(hours=time_window_hours)
        self.model = IsolationForest(contamination=threshold)
    
    def preprocess_logs(self, log_file):
        """
        Load and preprocess the log data.
        
        Parameters:
        - log_file: Path to the log file in JSON format.
        
        Returns:
        - DataFrame of filtered and processed logs.
        """
        # Load logs from JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to DataFrame
        df = pd.DataFrame(logs)
        
        # Filter for relevant Event IDs (6005, 6006, 6008)
        df = df[df['EventID'].isin([6005, 6006, 6008])]
        
        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        return df

    def detect_frequent_reboots(self, log_file):
        """
        Detect frequent reboots using Isolation Forest.
        
        Parameters:
        - log_file: Path to the log file in JSON format.
        
        Returns:
        - DataFrame of detected anomalies.
        """
        df = self.preprocess_logs(log_file)
        
        # Create a time window column that bins the timestamps into intervals
        df['WindowStart'] = df['Timestamp'].dt.floor('H')
        
        # Count the number of reboots in each time window
        reboot_counts = df.groupby('WindowStart').size().reset_index(name='RebootCount')
        
        # Train the Isolation Forest model
        self.model.fit(reboot_counts[['RebootCount']])
        
        # Detect anomalies
        reboot_counts['Anomaly'] = self.model.predict(reboot_counts[['RebootCount']])
        reboot_counts['Anomaly'] = reboot_counts['Anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
        
        # Filter anomalies
        anomalies = reboot_counts[reboot_counts['Anomaly'] == 'Anomaly']
        
        return anomalies

if __name__ == "__main__":
    detector = FrequentRebootDetector(time_window_hours=24)
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Detect frequent reboots
    anomalies = detector.detect_frequent_reboots(log_file)
    
    if not anomalies.empty:
        print("Frequent System Reboots Detected:")
        print(anomalies)
    else:
        print("No frequent system reboots detected.")
