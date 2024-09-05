# slow_performance_detector.py

import json

class SlowPerformanceDetector:
    """
    A class to detect slow system performance anomalies based on Windows Event Logs.
    """
    
    def __init__(self, log_data):
        """
        Initialize the detector with log data.
        
        :param log_data: List of log entries (dicts) from Windows Event Logs.
        """
        self.log_data = log_data
        self.performance_events = [
            # High CPU usage related event IDs
            {'event_id': 100, 'source': 'Microsoft-Windows-Diagnostics-Performance', 'level': 'Warning'},
            {'event_id': 2006, 'source': 'Microsoft-Windows-PerfNet', 'level': 'Error'},
            
            # Memory pressure related event IDs
            {'event_id': 2004, 'source': 'Microsoft-Windows-Resource-Exhaustion-Detector', 'level': 'Warning'},
            {'event_id': 2017, 'source': 'Microsoft-Windows-Resource-Exhaustion-Detector', 'level': 'Critical'},

            # Disk I/O related event IDs
            {'event_id': 129, 'source': 'Microsoft-Windows-StorPort', 'level': 'Warning'},
            {'event_id': 153, 'source': 'Disk', 'level': 'Warning'},
            
            # General slow performance indicators
            {'event_id': 1001, 'source': 'Microsoft-Windows-Winlogon', 'level': 'Information', 'description_contains': 'slow startup'}
        ]
    
    def detect(self):
        """
        Detects slow system performance anomalies in the logs.
        
        :return: List of detected anomalies.
        """
        detected_anomalies = []

        for log_entry in self.log_data:
            for event in self.performance_events:
                if (
                    log_entry.get('EventID') == event['event_id'] and
                    log_entry.get('Source') == event['source'] and
                    log_entry.get('Level') == event['level']
                ):
                    if 'description_contains' in event:
                        if event['description_contains'] in log_entry.get('Description', ''):
                            detected_anomalies.append(log_entry)
                    else:
                        detected_anomalies.append(log_entry)

        return detected_anomalies


if __name__ == "__main__":
    # Sample log data to test the module
    sample_logs = [
        {"EventID": 100, "Source": "Microsoft-Windows-Diagnostics-Performance", "Level": "Warning", "Description": "High CPU usage detected."},
        {"EventID": 2004, "Source": "Microsoft-Windows-Resource-Exhaustion-Detector", "Level": "Warning", "Description": "Memory pressure detected."},
        {"EventID": 129, "Source": "Microsoft-Windows-StorPort", "Level": "Warning", "Description": "Disk I/O delay warning."},
        {"EventID": 1001, "Source": "Microsoft-Windows-Winlogon", "Level": "Information", "Description": "The system boot was slow due to multiple processes."}
    ]

    detector = SlowPerformanceDetector(sample_logs)
    anomalies = detector.detect()
    
    print("Detected Slow System Performance Anomalies:")
    for anomaly in anomalies:
        print(anomaly)
