import json
from datetime import datetime, timedelta
from collections import defaultdict
from sklearn.ensemble import IsolationForest

class UnexpectedPrivilegeEscalationDetector:
    def __init__(self, logs_file):
        """
        Initialize the detector with a path to the logs file.
        :param logs_file: Path to the Windows event logs JSON file.
        """
        self.logs_file = logs_file
        self.escalation_events = ['4672', '4673', '4674']
        self.escalation_logs = []
        self.anomalies = []

    def load_logs(self):
        """
        Load logs from a JSON file.
        """
        with open(self.logs_file, 'r') as f:
            self.logs = json.load(f)
        print(f"Loaded {len(self.logs)} log entries.")

    def filter_escalation_logs(self):
        """
        Filter logs to get only privilege escalation-related logs.
        """
        for log in self.logs:
            if log.get('EventID') in self.escalation_events:
                self.escalation_logs.append(log)
        print(f"Filtered {len(self.escalation_logs)} escalation-related log entries.")

    def detect_anomalies(self):
        """
        Detect anomalies in the escalation logs using a combination of threshold-based and machine learning methods.
        """
        # Simple threshold-based detection
        user_access_count = defaultdict(int)
        for log in self.escalation_logs:
            user = log.get('User', 'Unknown')
            user_access_count[user] += 1

        # Flag users with unexpected high access
        for user, count in user_access_count.items():
            if count > 5:  # Example threshold for an unusual number of privilege escalations
                print(f"Anomaly Detected: User {user} has {count} privilege escalations.")

        # Machine Learning based anomaly detection using Isolation Forest
        self.anomaly_detection_with_isolation_forest()

    def anomaly_detection_with_isolation_forest(self):
        """
        Use Isolation Forest to detect anomalies in escalation logs.
        """
        # Preparing data for Isolation Forest
        data_points = []
        for log in self.escalation_logs:
            # Example features for model input
            timestamp = datetime.strptime(log.get('TimeGenerated', '1970-01-01 00:00:00'), '%Y-%m-%d %H:%M:%S')
            user = log.get('User', 'Unknown')
            event_id = log.get('EventID')
            data_points.append([timestamp.timestamp(), len(user), int(event_id)])
        
        if len(data_points) < 2:  # Isolation Forest needs at least 2 samples
            print("Not enough data for anomaly detection.")
            return
        
        # Train Isolation Forest
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        predictions = model.fit_predict(data_points)

        # Collect anomalies
        for i, log in enumerate(self.escalation_logs):
            if predictions[i] == -1:  # Anomaly detected
                self.anomalies.append(log)
        
        if self.anomalies:
            print("Anomalies detected in the escalation logs:")
            for anomaly in self.anomalies:
                print(f"Anomalous Event: {anomaly}")
        else:
            print("No anomalies detected.")

    def run(self):
        """
        Run the entire anomaly detection pipeline.
        """
        self.load_logs()
        self.filter_escalation_logs()
        self.detect_anomalies()


if __name__ == "__main__":
    # Example usage
    detector = UnexpectedPrivilegeEscalationDetector(logs_file='sample_windows_event_logs.json')
    detector.run()
