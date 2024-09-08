# network_interface_errors.py

import json

def detect_network_interface_errors(logs):
    """
    Detects network interface errors from Windows event logs.
    
    Args:
    - logs (list of dict): List of event logs in JSON format.
    
    Returns:
    - list of dict: List of detected anomalies related to network interface errors.
    """
    
    # Keywords or Event IDs related to network interface errors
    error_keywords = [
        "Network Interface",
        "NIC Failure",
        "Packet Drop",
        "Connection Error",
        "Link Down",
        "Media Disconnected"
    ]
    
    error_event_ids = [
        "1014",  # DNS Client Events (can indicate network issues)
        "10400", # NDIS (Network Driver Interface Specification) Network Interface Errors
        "4201",  # Network Link is disconnected
        "5000"   # Generic network adapter error
    ]
    
    detected_anomalies = []

    # Analyzing each log entry
    for log in logs:
        event_id = str(log.get("EventID", ""))
        message = log.get("Message", "").lower()
        
        # Check if the event ID matches known network error IDs or message contains error keywords
        if event_id in error_event_ids or any(keyword.lower() in message for keyword in error_keywords):
            detected_anomalies.append(log)
    
    return detected_anomalies


# Sample test function
if __name__ == "__main__":
    # Sample logs for testing
    sample_logs = [
        {
            "EventID": "1014",
            "Message": "Network Interface encountered a problem.",
            "TimeGenerated": "2024-09-08T10:22:31Z",
            "Source": "Microsoft-Windows-DNS-Client"
        },
        {
            "EventID": "5000",
            "Message": "NIC Failure detected on Network Adapter 1.",
            "TimeGenerated": "2024-09-08T12:45:11Z",
            "Source": "Microsoft-Windows-NDIS"
        },
        {
            "EventID": "4624",
            "Message": "An account was successfully logged on.",
            "TimeGenerated": "2024-09-08T13:15:09Z",
            "Source": "Microsoft-Windows-Security-Auditing"
        }
    ]
    
    anomalies = detect_network_interface_errors(sample_logs)
    print("Detected Network Interface Errors:")
    print(json.dumps(anomalies, indent=4))
