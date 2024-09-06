import re

class UnexpectedUserProfileChangesDetector:
    """
    This module detects unexpected changes to user profiles or settings based on event logs.
    """

    def __init__(self):
        # Event IDs related to user profile changes
        self.suspicious_event_ids = ['1500', '1502', '1503', '1511', '1515', '1517', '1530', '1533']

    def parse_event_log(self, log_entry):
        """
        Parses a log entry and returns a dictionary with key information.
        """
        log_pattern = r'EventID:\s*(\d+),\s*User:\s*([^,]+),\s*Description:\s*(.*)'
        match = re.search(log_pattern, log_entry)

        if match:
            event_id = match.group(1)
            user = match.group(2)
            description = match.group(3)
            return {
                'EventID': event_id,
                'User': user,
                'Description': description
            }
        return None

    def detect_anomaly(self, log_entries):
        """
        Detects unexpected user profile changes in a list of log entries.
        """
        anomalies = []
        for entry in log_entries:
            log_data = self.parse_event_log(entry)
            if log_data and log_data['EventID'] in self.suspicious_event_ids:
                anomalies.append({
                    'User': log_data['User'],
                    'EventID': log_data['EventID'],
                    'Description': log_data['Description']
                })

        return anomalies


# Example usage
if __name__ == "__main__":
    sample_logs = [
        "EventID: 1500, User: Alice, Description: User profile loaded successfully.",
        "EventID: 1511, User: Bob, Description: User profile service failed to load the user profile.",
        "EventID: 1530, User: Charlie, Description: Windows detected your registry file is still in use by other applications.",
        "EventID: 1502, User: Alice, Description: Windows cannot load the user's profile and is logging you on with a temporary profile."
    ]

    detector = UnexpectedUserProfileChangesDetector()
    anomalies = detector.detect_anomaly(sample_logs)
    print("Detected Anomalies:")
    for anomaly in anomalies:
        print(anomaly)
