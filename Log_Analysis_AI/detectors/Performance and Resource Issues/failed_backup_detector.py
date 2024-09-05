import json

class FailedBackupDetector:
    def __init__(self, log_file):
        self.log_file = log_file
        self.failure_event_ids = {12345, 12346}  # Example Event IDs for backup failures
        self.failure_threshold = 5  # Number of repeated failures to consider an anomaly
        self.failures = {}

    def parse_logs(self):
        with open(self.log_file, 'r') as file:
            logs = json.load(file)
        return logs

    def detect_anomalies(self, logs):
        for log in logs:
            event_id = log.get('EventID')
            if event_id in self.failure_event_ids:
                user = log.get('User')
                if user not in self.failures:
                    self.failures[user] = 0
                self.failures[user] += 1
        
        anomalies = []
        for user, count in self.failures.items():
            if count >= self.failure_threshold:
                anomalies.append({
                    'User': user,
                    'FailureCount': count
                })
        
        return anomalies

    def run_detection(self):
        logs = self.parse_logs()
        anomalies = self.detect_anomalies(logs)
        if anomalies:
            print("Anomalies Detected:")
            for anomaly in anomalies:
                print(f"User: {anomaly['User']}, Failure Count: {anomaly['FailureCount']}")
        else:
            print("No anomalies detected.")

if __name__ == "__main__":
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    detector = FailedBackupDetector(log_file)
    detector.run_detection()
