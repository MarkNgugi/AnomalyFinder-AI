import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_disk_space(logs):
    """
    Analyze logs to detect disk space exhaustion.
    Args:
    logs (list): List of log entries in JSON format.

    Returns:
    list: List of detected anomalies.
    """
    anomalies = []

    for log in logs:
        # Example log structure: {"EventID": 2013, "Message": "Low disk space on drive C: ..."}
        event_id = log.get("EventID")
        message = log.get("Message", "")

        # Check for specific event IDs related to low disk space
        if event_id == 2013 or event_id == 2020:
            if "low disk space" in message.lower() or "critical disk space" in message.lower():
                anomalies.append(log)
                logging.info(f"Anomaly detected: {log}")

    return anomalies

if __name__ == "__main__":
    # Sample logs for testing
    sample_logs = [
        {"EventID": 2013, "Message": "Low disk space on drive C: Only 1 GB remaining."},
        {"EventID": 2020, "Message": "Critical disk space warning on drive D: Less than 100 MB available."},
        {"EventID": 2021, "Message": "Disk space is normal on drive E: 50 GB free."},
        {"EventID": 2013, "Message": "Low disk space on drive C: 2 GB remaining."},
    ]

    detected_anomalies = check_disk_space(sample_logs)
    print("Detected anomalies:", detected_anomalies)

