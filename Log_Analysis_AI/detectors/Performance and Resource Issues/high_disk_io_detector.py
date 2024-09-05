# high_disk_io_detector.py

import json

class HighDiskIODetector:
    """
    A module to detect high disk I/O anomalies from Windows Event Logs.
    It identifies unusual or excessive disk input/output operations by analyzing relevant Event IDs.
    """

    # Relevant Event IDs for high disk I/O detection
    DISK_IO_EVENT_IDS = [7, 9, 11, 15, 129, 153]  # Disk errors, StorPort timeouts, Disk I/O errors
    DISK_IO_THRESHOLD = 5000  # Example threshold for bytes/sec for high disk I/O (adjust based on system)

    def __init__(self, log_file):
        """
        Initializes the HighDiskIODetector with a log file.
        :param log_file: Path to the JSON file containing Windows Event Logs
        """
        self.log_file = log_file

    def load_logs(self):
        """
        Load logs from the specified log file.
        """
        with open(self.log_file, 'r') as file:
            logs = json.load(file)
        return logs

    def detect_high_disk_io(self, logs):
        """
        Detect high disk I/O anomalies from the provided logs.
        :param logs: List of log entries to analyze
        :return: List of detected anomalies
        """
        anomalies = []
        for log in logs:
            # Check for relevant Event IDs indicating high disk I/O or related errors
            if log.get('EventID') in self.DISK_IO_EVENT_IDS:
                anomalies.append({
                    'Timestamp': log.get('TimeCreated'),
                    'EventID': log.get('EventID'),
                    'Message': log.get('Message'),
                    'Source': log.get('Source'),
                })
            
            # Example of checking performance counter data (optional)
            if log.get('Source') == 'PerfMon':
                if log.get('Counter') == 'Disk Write Bytes/sec' and log.get('Value', 0) > self.DISK_IO_THRESHOLD:
                    anomalies.append({
                        'Timestamp': log.get('TimeCreated'),
                        'Counter': log.get('Counter'),
                        'Value': log.get('Value'),
                        'Message': 'High Disk Write Rate detected',
                    })

        return anomalies

    def run(self):
        """
        Run the high disk I/O detection process.
        """
        logs = self.load_logs()
        anomalies = self.detect_high_disk_io(logs)
        if anomalies:
            print(f"Detected {len(anomalies)} high disk I/O anomalies:")
            for anomaly in anomalies:
                print(anomaly)
        else:
            print("No high disk I/O anomalies detected.")


# Example usage
if __name__ == '__main__':
    detector = HighDiskIODetector('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json')
    detector.run()
