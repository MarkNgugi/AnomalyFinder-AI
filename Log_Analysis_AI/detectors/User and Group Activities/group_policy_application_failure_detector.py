import re

class GroupPolicyApplicationFailureDetector:
    def __init__(self):
        # Define relevant Event IDs and keywords for Group Policy failures
        self.relevant_event_ids = [1058, 1085, 1006, 1202]  # Common Event IDs for Group Policy application failures
        self.keywords = ['Group Policy', 'failed', 'error', 'GPO', 'cannot apply', 'policy processing', 'denied']

    def parse_log_entry(self, log_entry):
        """
        Parse a single log entry to extract Event ID, Level, and Message.
        """
        event_id = log_entry.get('EventID')
        level = log_entry.get('Level')
        message = log_entry.get('Message')

        return event_id, level, message

    def detect_anomaly(self, log_entries):
        """
        Detect anomalies related to Group Policy Application Failures.
        """
        anomalies = []

        for log_entry in log_entries:
            event_id, level, message = self.parse_log_entry(log_entry)

            # Check if the Event ID is relevant for Group Policy Application Failures
            if event_id in self.relevant_event_ids:
                # Check if any keyword is present in the message
                if any(keyword.lower() in message.lower() for keyword in self.keywords):
                    anomalies.append(log_entry)

        return anomalies


# Sample usage
if __name__ == "__main__":
    # Sample log entries
    sample_logs = [
        {'EventID': 1058, 'Level': 'Error', 'Message': 'The processing of Group Policy failed. Windows attempted to read the file \\domain\Policies\{GUID}\gpt.ini from a domain controller and was not successful.'},
        {'EventID': 1085, 'Level': 'Warning', 'Message': 'Windows failed to apply the Group Policy Scripts settings. Group Policy settings might have its own log file. Please look for details there.'},
        {'EventID': 4624, 'Level': 'Information', 'Message': 'An account was successfully logged on.'},
        {'EventID': 1006, 'Level': 'Error', 'Message': 'The Group Policy Client Side Extension failed to apply one or more settings because of the following error: Access is denied.'},
        {'EventID': 1202, 'Level': 'Error', 'Message': 'Security policies were propagated with warning. 0x534: No mapping between account names and security IDs was done.'}
    ]

    # Initialize the detector
    detector = GroupPolicyApplicationFailureDetector()

    # Detect anomalies
    detected_anomalies = detector.detect_anomaly(sample_logs)

    # Print detected anomalies
    for anomaly in detected_anomalies:
        print(f"Anomaly Detected: EventID={anomaly['EventID']}, Level={anomaly['Level']}, Message={anomaly['Message']}")
