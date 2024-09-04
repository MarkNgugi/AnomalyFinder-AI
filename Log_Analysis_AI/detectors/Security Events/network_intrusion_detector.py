import json
from typing import List, Dict, Any

# Define event IDs related to potential network intrusion attempts
POTENTIAL_INTRUSION_EVENTS = {
    "Security": [5152, 5157, 5031],  # Blocking events in Security logs
    "Firewall": [5154, 5155],        # Port-related events in Firewall logs
    "System": [4690, 7036],          # Possible intrusion-related service changes
    # Add more event IDs that are associated with intrusion attempts
}

def detect_network_intrusion(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect potential network intrusion attempts from Windows event logs.

    Args:
        logs (List[Dict[str, Any]]): List of logs in dictionary format.

    Returns:
        List[Dict[str, Any]]: List of detected anomalies.
    """
    anomalies = []

    for log in logs:
        event_id = log.get('EventID')
        log_name = log.get('LogName')

        # Check if the log is from a relevant log source and has a potential intrusion event ID
        if log_name in POTENTIAL_INTRUSION_EVENTS and event_id in POTENTIAL_INTRUSION_EVENTS[log_name]:
            # Additional checks can be added here to filter out false positives
            anomalies.append({
                "Timestamp": log.get("TimeCreated"),
                "LogName": log_name,
                "EventID": event_id,
                "Message": log.get("Message"),
                "Source": log.get("Source"),
            })

    return anomalies

if __name__ == "__main__":
    # Load sample logs
    with open("/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json", "r") as f:
        logs = json.load(f)

    # Detect anomalies
    detected_anomalies = detect_network_intrusion(logs)

    # Print results
    if detected_anomalies:
        print("Potential Network Intrusion Attempts Detected:")
        for anomaly in detected_anomalies:
            print(f"Timestamp: {anomaly['Timestamp']}, Log: {anomaly['LogName']}, EventID: {anomaly['EventID']}, Message: {anomaly['Message']}")
    else:
        print("No potential network intrusion attempts detected.")
