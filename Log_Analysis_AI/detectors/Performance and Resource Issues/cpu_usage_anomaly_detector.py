import json
import re

class CPUUsageDetector:
    def __init__(self, threshold=80):
        """
        Initialize the CPUUsageDetector with a CPU usage threshold.
        
        Args:
            threshold (float): The CPU usage percentage that triggers an alert.
        """
        self.threshold = threshold
    
    def parse_log(self, log):
        """
        Parse the log entry to extract CPU usage information.
        
        Args:
            log (str): The log entry as a JSON string.
        
        Returns:
            dict: Parsed log information.
        """
        try:
            log_data = json.loads(log)
            return log_data
        except json.JSONDecodeError:
            print("Error decoding JSON log.")
            return None
    
    def detect_anomaly(self, log):
        """
        Detect anomalies in CPU usage from the log entry.
        
        Args:
            log (str): The log entry as a JSON string.
        
        Returns:
            dict: Anomaly details if detected, otherwise None.
        """
        log_data = self.parse_log(log)
        if log_data:
            try:
                cpu_usage = log_data.get('cpu_usage')
                if cpu_usage is not None:
                    if cpu_usage > self.threshold:
                        return {
                            'anomaly_type': 'High CPU Usage',
                            'cpu_usage': cpu_usage,
                            'log_entry': log
                        }
                    elif cpu_usage < 0 or cpu_usage > 100:
                        return {
                            'anomaly_type': 'Invalid CPU Usage',
                            'cpu_usage': cpu_usage,
                            'log_entry': log
                        }
            except KeyError:
                print("Expected key 'cpu_usage' not found in log.")
        
        return None

# Sample Usage
if __name__ == "__main__":
    sample_log = '{"timestamp": "2024-09-05T12:00:00Z", "process_name": "example.exe", "cpu_usage": 85}'
    detector = CPUUsageDetector(threshold=80)
    anomaly = detector.detect_anomaly(sample_log)
    if anomaly:
        print("Anomaly Detected:", anomaly)
    else:
        print("No Anomaly Detected.")
