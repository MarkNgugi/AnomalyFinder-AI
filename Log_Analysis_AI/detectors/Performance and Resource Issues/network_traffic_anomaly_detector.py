import json
import datetime

# Define threshold for detecting high network traffic (e.g., bytes per second)
TRAFFIC_THRESHOLD = 1000000  # Adjust this value based on your needs

def parse_log(log_line):
    """
    Parse a log line to extract timestamp and network traffic volume.
    Assumes log entries are in JSON format.
    """
    try:
        log_entry = json.loads(log_line)
        timestamp = datetime.datetime.fromisoformat(log_entry['timestamp'])
        traffic_volume = log_entry['network_traffic_bytes']  # Adjust based on actual log structure
        return timestamp, traffic_volume
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"Error parsing log line: {e}")
        return None, None

def detect_anomaly(log_lines):
    """
    Detect anomalies in network traffic based on predefined thresholds.
    """
    anomalies = []
    for log_line in log_lines:
        timestamp, traffic_volume = parse_log(log_line)
        if traffic_volume is not None:
            if traffic_volume > TRAFFIC_THRESHOLD:
                anomalies.append({
                    'timestamp': timestamp,
                    'traffic_volume': traffic_volume,
                    'status': 'Anomaly Detected'
                })
    return anomalies

def main():
    # Example log lines for testing
    sample_logs = [
        '{"timestamp": "2024-09-05T10:00:00", "network_traffic_bytes": 800000}',
        '{"timestamp": "2024-09-05T10:05:00", "network_traffic_bytes": 1200000}',  # Above threshold
        '{"timestamp": "2024-09-05T10:10:00", "network_traffic_bytes": 700000}',
        '{"timestamp": "2024-09-05T10:15:00", "network_traffic_bytes": 2000000}',  # Above threshold
    ]
    
    anomalies = detect_anomaly(sample_logs)
    if anomalies:
        for anomaly in anomalies:
            print(f"Anomaly Detected: {anomaly}")
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    main()
