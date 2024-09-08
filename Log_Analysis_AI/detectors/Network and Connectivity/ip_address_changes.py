import json
from collections import defaultdict
from datetime import datetime, timedelta

class IPAddressChangesDetector:
    def __init__(self, log_data, time_window_minutes=10, change_threshold=2):
        """
        Initializes the detector with log data and parameters for anomaly detection.
        
        :param log_data: List of dictionaries representing Windows event logs.
        :param time_window_minutes: The time window in minutes to look for multiple IP address changes.
        :param change_threshold: The number of IP changes within the time window to trigger an alert.
        """
        self.log_data = log_data
        self.time_window = timedelta(minutes=time_window_minutes)
        self.change_threshold = change_threshold

    def parse_logs(self):
        """
        Parses the log data to extract relevant information.
        
        :return: A dictionary mapping user IDs to a list of IP changes with timestamps.
        """
        ip_change_events = defaultdict(list)
        for entry in self.log_data:
            try:
                if entry.get("EventID") == 516:  # Assuming Event ID 516 is for IP change events
                    user = entry.get("User")
                    ip_address = entry.get("IPAddress")
                    timestamp = datetime.strptime(entry.get("TimeGenerated"), "%Y-%m-%d %H:%M:%S")
                    ip_change_events[user].append((timestamp, ip_address))
            except Exception as e:
                print(f"Error parsing log entry: {e}")
        return ip_change_events

    def detect_anomalies(self):
        """
        Detects anomalies in IP address changes based on the defined time window and change threshold.
        
        :return: A list of users with detected anomalies.
        """
        anomalies = []
        ip_change_events = self.parse_logs()

        for user, events in ip_change_events.items():
            events.sort()  # Sort by timestamp
            changes_in_window = []

            for i in range(len(events)):
                changes_in_window = [events[i]]

                for j in range(i + 1, len(events)):
                    if events[j][0] - events[i][0] <= self.time_window:
                        changes_in_window.append(events[j])
                    else:
                        break

                if len(changes_in_window) >= self.change_threshold:
                    anomalies.append({
                        "User": user,
                        "IPChanges": changes_in_window,
                        "ChangeCount": len(changes_in_window),
                        "AnomalyDetected": True
                    })
                    break

        return anomalies


if __name__ == "__main__":
    # Sample logs for testing
    with open('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json', 'r') as f:
        logs = json.load(f)

    detector = IPAddressChangesDetector(logs)
    anomalies = detector.detect_anomalies()

    if anomalies:
        print("Anomalies Detected:")
        for anomaly in anomalies:
            print(anomaly)
    else:
        print("No anomalies detected.")
