import pandas as pd
import json

class EventLogCorruptionDetector:
    def __init__(self):
        # Initialize any necessary parameters here
        pass
    
    def preprocess_logs(self, log_file):
        # Load logs from a JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)
        
        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Filter for Event Log Corruption related Event IDs
        # Event IDs for corruption issues
        corruption_event_ids = [1102, 104]  # Event ID 1102: Audit Log Cleared, Event ID 104: Event Log Corruption
        df = df[df['EventID'].isin(corruption_event_ids)]
        
        return df

    def detect_anomalies(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # If there are any corruption-related events
        if not df.empty:
            return df
        else:
            return None

if __name__ == "__main__":
    detector = EventLogCorruptionDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(log_file)
    
    if anomalies is not None:
        print("Event Log Corruption Detected:")
        print(anomalies)
    else:
        print("No event log corruption detected.")
