import pandas as pd
import json

class BSODDetector:
    def __init__(self):
        self.bsod_event_ids = [41]  # Event ID 41 indicates unexpected shutdowns due to BSOD

    def preprocess_logs(self, log_file):
        # Load the logs from a JSON file
        with open(log_file, 'r') as file:
            logs = json.load(file)

        # Convert logs to a DataFrame
        df = pd.DataFrame(logs)
        
        # Filter for BSOD related Event IDs
        df = df[df['EventID'].isin(self.bsod_event_ids)]

        # Convert 'Timestamp' to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        return df

    def detect_bsod(self, log_file):
        df = self.preprocess_logs(log_file)
        
        # If any BSOD events are found, return them
        if not df.empty:
            return df
        else:
            return None

if __name__ == "__main__":
    detector = BSODDetector()
    
    # Path to the log file
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Detect BSOD anomalies
    bsod_anomalies = detector.detect_bsod(log_file)
    
    if bsod_anomalies is not None:
        print("Blue Screen of Death (BSOD) Detected:")
        print(bsod_anomalies)
    else:
        print("No BSOD anomalies detected.")
