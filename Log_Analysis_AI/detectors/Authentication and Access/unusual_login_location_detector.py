import json
from typing import List, Dict, Any

def load_logs(file_path: str) -> List[Dict[str, Any]]:
    """
    Load and parse the logs from a JSON file.
    """
    with open(file_path, 'r') as file:
        return json.load(file)

def detect_unusual_logins(logs: List[Dict[str, Any]], unusual_locations: List[str]) -> List[Dict[str, Any]]:
    """
    Detect successful logins from unusual locations.

    :param logs: List of log entries, where each entry is a dictionary.
    :param unusual_locations: List of locations considered unusual.
    :return: List of log entries that are detected as anomalies.
    """
    anomalies = []

    for log in logs:
        if log["EventType"] == "Successful Login" and log["Location"] in unusual_locations:
            anomalies.append(log)

    return anomalies

def main():
    log_file ='/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'  # Hard-coded path to the logs
    unusual_locations_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/unusual_locations.txt'  # Update this to your actual path if needed
    
    logs = load_logs(log_file)
    
    with open(unusual_locations_file, 'r') as file:
        unusual_locations = file.read().splitlines()

    anomalies = detect_unusual_logins(logs, unusual_locations)

    if anomalies:
        print("Detected anomalies:")
        for anomaly in anomalies:
            print(anomaly)
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    main()
