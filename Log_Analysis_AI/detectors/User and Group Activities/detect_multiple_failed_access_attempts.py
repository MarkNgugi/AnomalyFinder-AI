import pandas as pd
from datetime import datetime, timedelta

class DetectMultipleFailedAccessAttempts:
    def __init__(self, max_attempts=5, time_window_minutes=15):
        """
        Initializes the detection module for multiple failed access attempts.
        
        :param max_attempts: The number of failed attempts to consider an anomaly.
        :param time_window_minutes: The time window (in minutes) to check for multiple attempts.
        """
        self.max_attempts = max_attempts
        self.time_window = timedelta(minutes=time_window_minutes)
    
    def parse_logs(self, logs):
        """
        Parses the event logs and filters for Event ID 4625 (Failed login attempts).
        
        :param logs: A list of dictionaries containing event logs.
        :return: A DataFrame filtered for Event ID 4625.
        """
        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)
        # Filter logs for failed access attempts (Event ID 4625)
        df = df[df['EventID'] == 4625]
        # Convert TimeCreated to datetime
        df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])
        return df
    
    def detect_anomalies(self, logs):
        """
        Detects anomalies based on multiple failed access attempts.
        
        :param logs: A list of dictionaries containing event logs.
        :return: A list of anomalies detected.
        """
        df = self.parse_logs(logs)
        
        # Group by user and/or IP address
        grouped = df.groupby(['TargetUserName', 'IpAddress'])
        
        anomalies = []
        for (user, ip), group in grouped:
            # Sort by TimeCreated
            group = group.sort_values('TimeCreated')
            
            # Sliding window to detect multiple failed attempts
            for i in range(len(group)):
                window = group.iloc[i:]
                # Define the time window
                window = window[window['TimeCreated'] <= window.iloc[0]['TimeCreated'] + self.time_window]
                
                if len(window) >= self.max_attempts:
                    anomalies.append({
                        'User': user,
                        'IP': ip,
                        'FailedAttempts': len(window),
                        'TimeWindow': f"{window.iloc[0]['TimeCreated']} - {window.iloc[-1]['TimeCreated']}"
                    })
                    break  # Exit after detecting the first anomaly within the window
        
        return anomalies

# Sample usage
if __name__ == "__main__":
    sample_logs = [
        {"EventID": 4625, "TimeCreated": "2024-09-06T10:00:00", "TargetUserName": "user1", "IpAddress": "192.168.1.1"},
        {"EventID": 4625, "TimeCreated": "2024-09-06T10:02:00", "TargetUserName": "user1", "IpAddress": "192.168.1.1"},
        {"EventID": 4625, "TimeCreated": "2024-09-06T10:05:00", "TargetUserName": "user1", "IpAddress": "192.168.1.1"},
        {"EventID": 4625, "TimeCreated": "2024-09-06T10:07:00", "TargetUserName": "user1", "IpAddress": "192.168.1.1"},
        {"EventID": 4625, "TimeCreated": "2024-09-06T10:10:00", "TargetUserName": "user1", "IpAddress": "192.168.1.1"},
        {"EventID": 4625, "TimeCreated": "2024-09-06T10:15:00", "TargetUserName": "user2", "IpAddress": "192.168.1.2"}
    ]

    detector = DetectMultipleFailedAccessAttempts(max_attempts=4, time_window_minutes=15)
    anomalies = detector.detect_anomalies(sample_logs)
    
    for anomaly in anomalies:
        print(f"Anomaly detected: User {anomaly['User']} from IP {anomaly['IP']} had {anomaly['FailedAttempts']} failed attempts within {anomaly['TimeWindow']}.")
