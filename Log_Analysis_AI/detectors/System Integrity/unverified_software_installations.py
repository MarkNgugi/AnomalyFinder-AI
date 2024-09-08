import json

class UnverifiedSoftwareInstallationsDetector:
    def __init__(self):
        # Define the event IDs related to software installations (Event ID 11707 for MsiInstaller)
        self.relevant_event_ids = [11707]

    def is_untrusted_source(self, source):
        # Example check for untrusted sources; extend this logic as needed
        untrusted_sources = ['unknown', 'unverified', 'non-corporate']
        for untrusted in untrusted_sources:
            if untrusted.lower() in source.lower():
                return True
        return False

    def detect(self, log_entry):
        """
        Detect unverified software installations.
        Args:
        - log_entry (dict): A dictionary representing a Windows event log entry.
        Returns:
        - bool: True if an unverified software installation is detected; False otherwise.
        """
        # Check if the event ID matches the installation-related event
        if log_entry.get('EventID') in self.relevant_event_ids:
            # Check if the source is untrusted
            source = log_entry.get('Source', '')
            if self.is_untrusted_source(source):
                return True
        return False

    def analyze_logs(self, logs):
        """
        Analyze a list of logs and identify unverified software installations.
        Args:
        - logs (list): A list of dictionaries representing Windows event log entries.
        Returns:
        - list: A list of dictionaries representing the detected anomalies.
        """
        anomalies = []
        for log in logs:
            if self.detect(log):
                anomalies.append(log)
        return anomalies


# Example usage
if __name__ == "__main__":
    # Sample log entries for testing
    sample_logs = [
        {
            "EventID": 11707,
            "Source": "unknown software installer",
            "Message": "Installation of software XYZ completed."
        },
        {
            "EventID": 11707,
            "Source": "trusted corporate installer",
            "Message": "Installation of software ABC completed."
        },
        {
            "EventID": 7045,
            "Source": "Service Control Manager",
            "Message": "A service was installed in the system."
        }
    ]

    detector = UnverifiedSoftwareInstallationsDetector()
    anomalies = detector.analyze_logs(sample_logs)

    # Print detected anomalies
    if anomalies:
        print("Unverified software installations detected:")
        for anomaly in anomalies:
            print(json.dumps(anomaly, indent=2))
    else:
        print("No unverified software installations detected.")
