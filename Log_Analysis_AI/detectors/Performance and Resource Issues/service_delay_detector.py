import json
from datetime import datetime

# Define a list of critical services to monitor
CRITICAL_SERVICES = ['ServiceName1', 'ServiceName2']  # Replace with actual service names

# Define thresholds (in milliseconds) for identifying delays
START_DELAY_THRESHOLD = 10000  # 10 seconds
STOP_DELAY_THRESHOLD = 10000   # 10 seconds

def parse_event_log(log_entry):
    """
    Parse a single log entry.
    """
    try:
        event_id = log_entry.get('EventID')
        service_name = log_entry.get('ServiceName')
        timestamp = log_entry.get('Timestamp')
        message = log_entry.get('Message')
        
        if not event_id or not service_name or not timestamp:
            return None

        return {
            'event_id': event_id,
            'service_name': service_name,
            'timestamp': datetime.fromisoformat(timestamp),
            'message': message
        }
    except Exception as e:
        print(f"Error parsing log entry: {e}")
        return None

def analyze_log(log_entry):
    """
    Analyze the log entry to detect service delays.
    """
    parsed_log = parse_event_log(log_entry)
    if not parsed_log:
        return None

    event_id = parsed_log['event_id']
    service_name = parsed_log['service_name']
    timestamp = parsed_log['timestamp']
    message = parsed_log['message']

    if service_name not in CRITICAL_SERVICES:
        return None

    if event_id == 7000:  # Example Event ID for service start failure
        if 'timeout' in message.lower():
            return f"Service '{service_name}' delayed in starting. Event occurred at {timestamp}."

    elif event_id == 7009:  # Example Event ID for service stop failure
        if 'timeout' in message.lower():
            return f"Service '{service_name}' delayed in stopping. Event occurred at {timestamp}."

    return None

def process_logs(log_file):
    """
    Process the logs from a JSON file and detect service delays.
    """
    with open(log_file, 'r') as file:
        logs = json.load(file)

    results = []
    for log_entry in logs:
        result = analyze_log(log_entry)
        if result:
            results.append(result)

    return results

if __name__ == "__main__":
    # Sample log file path
    log_file_path = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    detected_anomalies = process_logs(log_file_path)
    for anomaly in detected_anomalies:
        print(anomaly)
