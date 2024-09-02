import json
from typing import List, Dict, Any

def load_logs(file_path: str) -> List[Dict[str, Any]]:
    """
    Load and parse the logs from a JSON file.
    """
    with open(file_path, 'r') as file:
        return json.load(file)

def load_disabled_accounts(file_path: str) -> List[str]:
    """
    Load the list of disabled accounts from a file.

    :param file_path: Path to the file containing disabled accounts.
    :return: List of disabled account names.
    """
    with open(file_path, 'r') as file:
        return file.read().splitlines()

def detect_login_attempts_from_disabled_accounts(logs: List[Dict[str, Any]], disabled_accounts: List[str]) -> List[Dict[str, Any]]:
    """
    Detect login attempts from disabled accounts.

    :param logs: List of log entries, where each entry is a dictionary.
    :param disabled_accounts: List of account names that are disabled.
    :return: List of log entries that are detected as anomalies.
    """
    anomalies = []

    for log in logs:
        if log["EventType"] == "Login Attempt" and log["AccountName"] in disabled_accounts:
            anomalies.append(log)

    return anomalies

def main():
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'  # Update this to your actual path
    disabled_accounts_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/disabled_accounts.txt'  # Update this to your actual path
    
    logs = load_logs(log_file)
    disabled_accounts = load_disabled_accounts(disabled_accounts_file)

    anomalies = detect_login_attempts_from_disabled_accounts(logs, disabled_accounts)

    if anomalies:
        print("Detected anomalies:")
        for anomaly in anomalies:
            print(anomaly)
    else:
        print("No anomalies detected.")

if __name__ == "__main__":
    main()
