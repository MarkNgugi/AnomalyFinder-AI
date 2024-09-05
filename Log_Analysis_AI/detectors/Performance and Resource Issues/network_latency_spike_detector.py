# network_latency_spike_detector.py

import json
from datetime import datetime, timedelta

class NetworkLatencySpikeDetector:
    """
    This class detects network latency spikes or connectivity issues from Windows Event Logs.
    """

    def __init__(self, threshold_minutes=5):
        """
        Initialize the detector with a threshold for identifying spikes.

        :param threshold_minutes: The time threshold in minutes for considering events as spikes.
        """
        self.threshold_minutes = threshold_minutes
        self.latency_event_ids = [1014]  # DNS Client Events - Name resolution timeout
        self.connectivity_event_ids = [4201, 4202]  # TCPIP Events - Connection and disconnection issues

    def parse_logs(self, logs):
        """
        Parse the provided logs and convert them to a list of dictionaries.

        :param logs: JSON formatted logs as a string.
        :return: List of parsed log dictionaries.
        """
        return json.loads(logs)

    def detect_anomalies(self, logs):
        """
        Detect network latency spikes or connectivity issues in the logs.

        :param logs: List of log entries as dictionaries.
        :return: List of detected anomalies.
        """
        anomalies = []
        sorted_logs = sorted(logs, key=lambda x: datetime.fromisoformat(x['TimeCreated']))
        last_latency_event_time = None

        for log in sorted_logs:
            event_id = log.get("EventID")
            time_created = datetime.fromisoformat(log["TimeCreated"])
            message = log.get("Message", "")

            # Check for network latency (DNS) events
            if event_id in self.latency_event_ids and "timed out" in message:
                if last_latency_event_time:
                    # Calculate time difference between consecutive latency events
                    time_diff = time_created - last_latency_event_time
                    if time_diff <= timedelta(minutes=self.threshold_minutes):
                        anomalies.append({
                            "TimeCreated": time_created.isoformat(),
                            "EventID": event_id,
                            "Source": log.get("Source"),
                            "Message": message,
                            "AnomalyType": "Network Latency Spike Detected"
                        })
                last_latency_event_time = time_created

            # Check for network connectivity (TCPIP) events
            elif event_id in self.connectivity_event_ids:
                anomalies.append({
                    "TimeCreated": time_created.isoformat(),
                    "EventID": event_id,
                    "Source": log.get("Source"),
                    "Message": message,
                    "AnomalyType": "Network Connectivity Issue Detected"
                })

        return anomalies

# Sample usage
if __name__ == "__main__":
    # Sample logs in JSON format
    sample_logs = '''[
        {"EventID": 1014, "Source": "DNS Client Events", "TimeCreated": "2024-09-05T10:15:30", "Message": "Name resolution for the name example.com timed out after none of the configured DNS servers responded."},
        {"EventID": 4201, "Source": "TCPIP", "TimeCreated": "2024-09-05T10:18:45", "Message": "The system detected that network adapter Ethernet has connected to the network, but a delay occurred during network initialization."},
        {"EventID": 1014, "Source": "DNS Client Events", "TimeCreated": "2024-09-05T10:20:12", "Message": "Name resolution for the name another-example.com timed out after none of the configured DNS servers responded."},
        {"EventID": 4202, "Source": "TCPIP", "TimeCreated": "2024-09-05T10:21:50", "Message": "The system detected that network adapter Ethernet has been disconnected from the network."},
        {"EventID": 1014, "Source": "DNS Client Events", "TimeCreated": "2024-09-05T10:25:30", "Message": "Name resolution for the name example.com was successful after a delay."}
    ]'''

    detector = NetworkLatencySpikeDetector()
    parsed_logs = detector.parse_logs(sample_logs)
    anomalies = detector.detect_anomalies(parsed_logs)

    print("Detected Anomalies:")
    for anomaly in anomalies:
        print(json.dumps(anomaly, indent=4))
