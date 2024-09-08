import json
from datetime import datetime, timedelta

class FailedServiceStartDetector:
    def __init__(self, threshold=10, timeframe=60):
        self.threshold = threshold
        self.timeframe = timeframe  # Timeframe in minutes

    def parse_log(self, log_data):
        return [entry for entry in log_data if entry.get('event_id') == 7000 and entry.get('event_type') == 'Error']

    def detect_anomalies(self, log_data):
        failed_starts = self.parse_log(log_data)
        now = datetime.now()
        time_limit = now - timedelta(minutes=self.timeframe)
        
        recent_failures = [entry for entry in failed_starts if datetime.fromisoformat(entry['timestamp']) > time_limit]
        
        if len(recent_failures) > self.threshold:
            return {
                'anomaly': 'High Number of Failed Service Starts',
                'count': len(recent_failures),
                'threshold': self.threshold,
                'timeframe': self.timeframe
            }
        return None

def main(log_file):
    with open(log_file, 'r') as file:
        log_data = json.load(file)
    
    detector = FailedServiceStartDetector()
    anomaly = detector.detect_anomalies(log_data)
    
    if anomaly:
        print("Anomaly detected:", anomaly)
    else:
        print("No anomaly detected.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python high_failed_service_starts.py <log_file>")
    else:
        main(sys.argv[1])
