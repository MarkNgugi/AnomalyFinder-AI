import json
from sklearn.ensemble import IsolationForest
import pandas as pd
from datetime import datetime, timedelta

class AccountLockoutDetector:
    def __init__(self, log_file='sample_logs.json', lockout_threshold=3, time_window=60):
        """
        Initialize the AccountLockoutDetector.

        Args:
        - log_file (str): Path to the log file.
        - lockout_threshold (int): Number of lockouts considered anomalous within the time window.
        - time_window (int): Time window in minutes for detecting frequent lockouts.
        """
        self.log_file = log_file
        self.lockout_threshold = lockout_threshold
        self.time_window = time_window
        self.logs = []
        self.df = None

    def load_logs(self):
        """Load logs from a JSON file."""
        try:
            with open(self.log_file, 'r') as f:
                self.logs = json.load(f)
            print(f"Loaded {len(self.logs)} logs successfully.")
        except FileNotFoundError:
            print("Log file not found.")
    
    def filter_lockout_events(self):
        """Filter out account lockout events from logs."""
        filtered_logs = []
        for log in self.logs:
            if log.get("EventID") == "4740":  # Event ID 4740 is for account lockout in Windows
                filtered_logs.append({
                    "Timestamp": datetime.strptime(log.get("TimeCreated"), "%Y-%m-%d %H:%M:%S"),
                    "AccountName": log.get("TargetUserName"),
                    "LogonType": log.get("LogonType")
                })
        self.df = pd.DataFrame(filtered_logs)
        print(f"Filtered {len(self.df)} account lockout events.")

    def detect_anomalies(self):
        """
        Detect anomalies based on frequent account lockouts within the time window.

        Returns:
        - anomalies (List[Dict]): List of detected anomalies with details.
        """
        anomalies = []
        
        if self.df.empty:
            print("No account lockout events to analyze.")
            return anomalies
        
        # Sort DataFrame by Timestamp
        self.df.sort_values(by='Timestamp', inplace=True)

        # Group by AccountName to detect frequent lockouts
        for account, group in self.df.groupby('AccountName'):
            group = group.set_index('Timestamp')
            group = group.resample(f'{self.time_window}T').count()

            # Apply threshold detection
            frequent_lockouts = group[group['LogonType'] > self.lockout_threshold]
            if not frequent_lockouts.empty:
                for timestamp, row in frequent_lockouts.iterrows():
                    anomalies.append({
                        "AccountName": account,
                        "Timestamp": timestamp,
                        "LockoutCount": row['LogonType']
                    })
        
        return anomalies

    def print_anomalies(self, anomalies):
        """Print detected anomalies."""
        if anomalies:
            print("Anomalies Detected:")
            for anomaly in anomalies:
                print(f"Account: {anomaly['AccountName']}, Time: {anomaly['Timestamp']}, Lockout Count: {anomaly['LockoutCount']}")
        else:
            print("No anomalies detected.")

if __name__ == "__main__":
    detector = AccountLockoutDetector(log_file='/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json', lockout_threshold=3, time_window=60)
    detector.load_logs()
    detector.filter_lockout_events()
    anomalies = detector.detect_anomalies()
    detector.print_anomalies(anomalies)
