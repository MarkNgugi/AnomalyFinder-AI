import json
from typing import List, Dict, Any
from datetime import datetime, timedelta

def load_logs(file_path: str) -> List[Dict[str, Any]]:
    """
    Load and parse the logs from a JSON file.
    """
    with open(file_path, 'r') as file:
        return json.load(file)

def detect_multiple_concurrent_logins(logs: List[Dict[str, Any]], time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """
    Detect multiple concurrent logins from different IPs or systems within a time window.

    :param logs: List of log entries, where each entry is a dictionary.
    :param time_window_minutes: Time window in minutes to check for concurrent logins.
    :return: List of log entries that are detected as anomalies.
    """
    anomalies = []
    user_login_attempts = {}

    # Group logins by AccountName
    for log in logs:
        if log["EventType"] == "Successful Login":
            account_name = log["AccountName"]
            timestamp = datetime.strptime(log["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            source_ip = log.get("SourceIP", None)

            if account_name not in user_login_attempts:
                user_login_attempts[account_name] = []

            user_login_attempts[account_name].append({"timestamp": timestamp, "source_ip": source_ip, "log": log})

    # Detect concurrent logins
    for account, attempts in user_login_attempts.items():
        attempts.sort(key=lambda x: x["timestamp"])  # Sort by timestamp

        for i in range(len(attempts)):
            current_attempt = attempts[i]
            concurrent_attempts = []

            # Check for logins within the time window
            for j in range(i + 1, len(attempts)):
                next_attempt = attempts[j]
                if next_attempt["timestamp"] - current_attempt["timestamp"] <= timedelta(minutes=time_window_minutes):
                    # Check if logins are from different IPs
                    if current_attempt["source_ip"] != next_attempt["source_ip"]:
                        concurrent_attempts.append(next_attempt["log"])
                else:
                    break

            # If multiple concurrent logins are detected, add them to anomalies
            if concurrent_attempts:
                concurrent_attempts.insert(0, current_attempt["log"])  # Include the first attempt
                anomalies.extend(concurrent_attempts)

    return anomalies

def main():
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'  # Update this to your actual path
    
    logs = load_logs(log_file)
    anomalies = detect_multiple_concurrent_logins(logs, time_window_minutes=5)

    if anomalies:
        print("Detected anomalies (Multiple Concurrent Logins):")
        for anomaly in anomalies:
            print(anomaly)
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    main()
