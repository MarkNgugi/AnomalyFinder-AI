# log_clearing_detector.py

import json
from typing import List, Dict

def detect_event_log_clearing(logs: List[Dict]) -> List[Dict]:
    """
    Detects anomalies related to the clearing or modification of event log entries.

    Args:
        logs (List[Dict]): List of log entries in dictionary format.

    Returns:
        List[Dict]: List of anomalies detected.
    """
    # Event IDs that indicate log clearing or modification
    log_clearing_event_ids = [1102, 104, 517]  # 1102: Security log cleared, 104: Application log cleared, 517: older systems
    
    # List to store detected anomalies
    anomalies = []

    # Loop through each log entry and check for log clearing events
    for log in logs:
        event_id = log.get("EventID")
        if event_id in log_clearing_event_ids:
            anomalies.append(log)

    return anomalies

def main():
    # Load sample logs from a JSON file
    with open('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json', 'r') as f:
        logs = json.load(f)

    # Detect anomalies
    anomalies = detect_event_log_clearing(logs)

    # Print detected anomalies
    if anomalies:
        print("Detected Event Log Clearing Anomalies:")
        for anomaly in anomalies:
            print(json.dumps(anomaly, indent=4))
    else:
        print("No anomalies related to event log clearing detected.")

if __name__ == "__main__":
    main()
