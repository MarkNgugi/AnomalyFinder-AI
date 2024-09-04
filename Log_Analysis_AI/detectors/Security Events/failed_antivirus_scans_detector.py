import json
from collections import defaultdict
from datetime import datetime, timedelta

def parse_datetime(datetime_str):
    """Parse the datetime string from the log and return a datetime object."""
    return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")

def detect_failed_antivirus_scans(logs, failure_event_id='3001', time_frame_minutes=60, failure_threshold=3):
    """
    Detects repeated failed antivirus scans from Windows event logs.

    Args:
    - logs (list of dicts): List of parsed log entries.
    - failure_event_id (str): Event ID for failed antivirus scans (default is '3001' for Windows Defender).
    - time_frame_minutes (int): Time frame in minutes to check for repeated failures.
    - failure_threshold (int): Number of failures in the specified time frame to consider as an anomaly.

    Returns:
    - list of dicts: Detected anomalies with timestamps and count.
    """
    anomalies = []
    failure_counts = defaultdict(int)

    # Convert time frame to timedelta
    time_frame = timedelta(minutes=time_frame_minutes)

    # Filter and analyze logs
    for log in logs:
        if log['EventID'] == failure_event_id:
            timestamp = parse_datetime(log['Timestamp'])
            failure_counts[timestamp] += 1
            
            # Remove outdated entries
            for old_timestamp in list(failure_counts.keys()):
                if timestamp - old_timestamp > time_frame:
                    del failure_counts[old_timestamp]

            # Check if failures exceed the threshold
            total_failures = sum(failure_counts.values())
            if total_failures >= failure_threshold:
                anomalies.append({
                    "Anomaly": "Repeated Failed Antivirus Scans",
                    "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "Failure Count": total_failures
                })
                # Clear count after detecting an anomaly to avoid duplicate reporting
                failure_counts.clear()

    return anomalies

# Sample logs for testing
sample_logs = [
    {"EventID": "3001", "Timestamp": "2024-09-03 10:00:00", "Message": "Antivirus scan failed"},
    {"EventID": "3001", "Timestamp": "2024-09-03 10:10:00", "Message": "Antivirus scan failed"},
    {"EventID": "3001", "Timestamp": "2024-09-03 10:20:00", "Message": "Antivirus scan failed"},
    {"EventID": "3001", "Timestamp": "2024-09-03 11:30:00", "Message": "Antivirus scan failed"},
    {"EventID": "3001", "Timestamp": "2024-09-03 11:35:00", "Message": "Antivirus scan failed"},
    {"EventID": "3001", "Timestamp": "2024-09-03 11:40:00", "Message": "Antivirus scan failed"},
    {"EventID": "1000", "Timestamp": "2024-09-03 12:00:00", "Message": "Other event not related to antivirus"}
]

# Run the anomaly detection module
anomalies_detected = detect_failed_antivirus_scans(sample_logs, failure_event_id='3001', time_frame_minutes=60, failure_threshold=3)

# Output detected anomalies
print("Detected Anomalies:")
for anomaly in anomalies_detected:
    print(anomaly)
