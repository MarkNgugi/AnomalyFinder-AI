# suspicious_traffic_patterns.py

import json
from collections import defaultdict

class SuspiciousTrafficPatternsDetector:
    def __init__(self):
        # Thresholds for detecting suspicious patterns
        self.thresholds = {
            'high_volume': 1000,  # Example threshold for high volume of traffic
            'frequent_connections': 100,  # Example threshold for frequent connections
        }
        self.traffic_data = defaultdict(lambda: {'count': 0, 'sources': set(), 'destinations': set()})

    def analyze_log(self, log_entry):
        """
        Analyzes a single log entry for suspicious traffic patterns.
        
        Parameters:
        log_entry (dict): A dictionary representing a log entry.
        
        Returns:
        dict: A dictionary containing the result of the analysis.
        """
        if log_entry['EventID'] == 5156:  # Windows Filtering Platform has allowed a connection
            source_ip = log_entry['SourceAddress']
            destination_ip = log_entry['DestinationAddress']
            source_port = log_entry['SourcePort']
            destination_port = log_entry['DestinationPort']

            key = f"{source_ip}:{destination_ip}:{destination_port}"
            self.traffic_data[key]['count'] += 1
            self.traffic_data[key]['sources'].add(source_ip)
            self.traffic_data[key]['destinations'].add(destination_ip)

            return self.detect_anomalies(key)

        return None

    def detect_anomalies(self, key):
        """
        Detects anomalies based on traffic data.

        Parameters:
        key (str): A unique key representing a traffic pattern.
        
        Returns:
        dict: A dictionary containing the anomaly detected.
        """
        pattern_data = self.traffic_data[key]

        # Detect high volume traffic
        if pattern_data['count'] > self.thresholds['high_volume']:
            return {
                'anomaly_type': 'High Traffic Volume',
                'description': f"High volume of traffic detected between {key}.",
                'details': pattern_data
            }
        
        # Detect frequent connections
        if len(pattern_data['sources']) > self.thresholds['frequent_connections']:
            return {
                'anomaly_type': 'Frequent Connections',
                'description': f"Frequent connections detected from multiple sources to {key}.",
                'details': pattern_data
            }

        return None

    def analyze_logs(self, logs):
        """
        Analyzes multiple log entries for suspicious traffic patterns.
        
        Parameters:
        logs (list): A list of dictionaries representing log entries.
        
        Returns:
        list: A list of dictionaries containing detected anomalies.
        """
        anomalies = []
        for log_entry in logs:
            result = self.analyze_log(log_entry)
            if result:
                anomalies.append(result)
        return anomalies

# Example usage
if __name__ == "__main__":
    # Load sample logs from JSON file or directly input
    sample_logs = [

  {
    "EventID": 5156,
    "TimeGenerated": "2024-09-08T12:00:00",
    "SourceAddress": "192.168.1.10",
    "DestinationAddress": "10.0.0.5",
    "SourcePort": "54321",
    "DestinationPort": "80"
  },
  {
    "EventID": 5156,
    "TimeGenerated": "2024-09-08T12:01:00",
    "SourceAddress": "192.168.1.11",
    "DestinationAddress": "10.0.0.5",
    "SourcePort": "54322",
    "DestinationPort": "80"
  },
  {
    "EventID": 5156,
    "TimeGenerated": "2024-09-08T12:02:00",
    "SourceAddress": "192.168.1.12",
    "DestinationAddress": "10.0.0.5",
    "SourcePort": "54323",
    "DestinationPort": "80"
  },
  {
    "EventID": 5156,
    "TimeGenerated": "2024-09-08T12:03:00",
    "SourceAddress": "192.168.1.10",
    "DestinationAddress": "10.0.0.5",
    "SourcePort": "54321",
    "DestinationPort": "80"
  },
  {
    "EventID": 5156,
    "TimeGenerated": "2024-09-08T12:04:00",
    "SourceAddress": "192.168.1.10",
    "DestinationAddress": "10.0.0.6",
    "SourcePort": "54321",
    "DestinationPort": "443"
  }

    ]

    detector = SuspiciousTrafficPatternsDetector()
    anomalies = detector.analyze_logs(sample_logs)
    
    if anomalies:
        print("Anomalies detected:")
        for anomaly in anomalies:
            print(json.dumps(anomaly, indent=2))
    else:
        print("No anomalies detected.")
