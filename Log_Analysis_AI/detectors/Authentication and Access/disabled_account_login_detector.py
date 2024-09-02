import json
from typing import List, Dict

class DisabledAccountLoginDetector:
    def __init__(self, disabled_accounts: List[str]):
        self.disabled_accounts = disabled_accounts

    def load_logs(self, file_path: str) -> List[Dict]:
        """
        Load logs from a JSON file.
        :param file_path: Path to the JSON file containing the logs.
        :return: List of log entries.
        """
        with open(file_path, 'r') as file:
            logs = json.load(file)
        return logs

    def detect_disabled_account_logins(self, logs: List[Dict]) -> List[Dict]:
        """
        Detect logins using disabled accounts.
        :param logs: List of log entries.
        :return: List of logs where disabled accounts attempted to login.
        """
        anomalies = []
        for log in logs:
            account_name = log.get('AccountName')
            if account_name in self.disabled_accounts:
                anomalies.append(log)
        return anomalies

    def report_anomalies(self, anomalies: List[Dict]):
        """
        Report the detected anomalies.
        :param anomalies: List of detected anomalies.
        """
        if anomalies:
            print(f"Found {len(anomalies)} login attempts using disabled accounts:")
            for anomaly in anomalies:
                print(json.dumps(anomaly, indent=2))
        else:
            print("No anomalies detected.")

if __name__ == "__main__":
    # Example usage:
    detector = DisabledAccountLoginDetector(disabled_accounts=['user1', 'user2'])
    
    # Load logs from a file
    logs = detector.load_logs('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json')
    
    # Detect anomalies
    anomalies = detector.detect_disabled_account_logins(logs)
    
    # Report anomalies
    detector.report_anomalies(anomalies)
