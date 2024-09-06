import re
from datetime import datetime, timedelta
from collections import defaultdict

def parse_event_time(event_time_str):
    """Parses event time from log string to a datetime object."""
    return datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S")

def is_port_scanning(event_logs, threshold=5, time_window_minutes=5):
    """
    Detects unusual port scanning activities from event logs.

    Parameters:
    - event_logs: List of dictionaries representing parsed event logs.
    - threshold: Number of connection attempts to different ports from the same IP to trigger an alert.
    - time_window_minutes: Time window in minutes to consider for scanning detection.

    Returns:
    - List of suspicious IP addresses with details of the scanning activity.
    """
    # Group logs by source IP address
    ip_connections = defaultdict(list)

    # Filter relevant logs (Event ID 5157 and 5152)
    for log in event_logs:
        if log['event_id'] in [5157, 5152]:
            ip_connections[log['source_ip']].append(log)

    # Detect port scanning
    suspicious_ips = []

    for ip, logs in ip_connections.items():
        # Sort logs by time
        logs.sort(key=lambda x: x['event_time'])
        
        # Sliding window approach to check for port scanning
        start = 0
        for end in range(len(logs)):
            # Check if the time difference is within the specified time window
            while (logs[end]['event_time'] - logs[start]['event_time']) > timedelta(minutes=time_window_minutes):
                start += 1

            # If number of different ports accessed is above the threshold, flag as suspicious
            unique_ports = len(set(log['destination_port'] for log in logs[start:end + 1]))
            if unique_ports >= threshold:
                suspicious_ips.append({
                    'ip': ip,
                    'total_attempts': len(logs[start:end + 1]),
                    'unique_ports': unique_ports,
                    'time_window': f"{logs[start]['event_time']} - {logs[end]['event_time']}"
                })
                break

    return suspicious_ips

# Sample test logs (You can replace these with actual logs for real testing)
sample_logs = [
    {'event_id': 5157, 'event_time': parse_event_time("2024-09-03 10:05:23"), 'source_ip': '192.168.1.100', 'destination_port': 22},
    {'event_id': 5157, 'event_time': parse_event_time("2024-09-03 10:05:45"), 'source_ip': '192.168.1.100', 'destination_port': 23},
    {'event_id': 5152, 'event_time': parse_event_time("2024-09-03 10:06:10"), 'source_ip': '192.168.1.100', 'destination_port': 80},
    {'event_id': 5157, 'event_time': parse_event_time("2024-09-03 10:06:30"), 'source_ip': '192.168.1.100', 'destination_port': 443},
    {'event_id': 5152, 'event_time': parse_event_time("2024-09-03 10:07:00"), 'source_ip': '192.168.1.100', 'destination_port': 8080},
    # Normal activity from another IP
    {'event_id': 5157, 'event_time': parse_event_time("2024-09-03 10:08:23"), 'source_ip': '192.168.1.101', 'destination_port': 22},
    {'event_id': 5157, 'event_time': parse_event_time("2024-09-03 10:10:23"), 'source_ip': '192.168.1.101', 'destination_port': 23},
]

# Run the detection module
suspicious_ips = is_port_scanning(sample_logs)
print("Suspicious IPs detected:", suspicious_ips)

