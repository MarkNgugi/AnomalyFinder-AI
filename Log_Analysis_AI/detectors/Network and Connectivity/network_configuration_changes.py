# network_configuration_changes.py

import json

class NetworkConfigurationChangesDetector:
    def __init__(self, approved_configurations=None):
        """
        Initializes the NetworkConfigurationChangesDetector with a list of approved network configurations.
        :param approved_configurations: A list of approved configurations (default: None)
        """
        # Define approved configurations if provided
        self.approved_configurations = approved_configurations if approved_configurations else []
    
    def is_change_authorized(self, log_entry):
        """
        Check if a change in the network configuration is authorized based on the provided log entry.
        :param log_entry: A dictionary representing a Windows Event Log entry
        :return: True if authorized, False if unauthorized
        """
        # Assuming the log entry contains details of the change in 'ConfigurationDetails' key
        configuration_change = log_entry.get("ConfigurationDetails", {})
        
        # Check if the change matches any approved configuration
        if configuration_change in self.approved_configurations:
            return True
        return False

    def detect_unauthorized_changes(self, logs):
        """
        Detects unauthorized network configuration changes from a list of logs.
        :param logs: A list of dictionaries representing Windows Event Log entries
        :return: A list of unauthorized change log entries
        """
        unauthorized_changes = []
        for log_entry in logs:
            if log_entry["EventID"] in [4199, 4200]:  # Event IDs related to network configuration changes
                if not self.is_change_authorized(log_entry):
                    unauthorized_changes.append(log_entry)
        return unauthorized_changes

if __name__ == "__main__":
    # Example usage
    sample_logs = [
        {
            "EventID": 4199,
            "ProviderName": "Microsoft-Windows-TCPIP",
            "EventRecordID": 12345,
            "TimeCreated": "2024-09-08T10:15:30",
            "ConfigurationDetails": {"IPAddress": "192.168.1.10"}
        },
        {
            "EventID": 4200,
            "ProviderName": "Microsoft-Windows-NetworkProfile",
            "EventRecordID": 12346,
            "TimeCreated": "2024-09-08T10:20:00",
            "ConfigurationDetails": {"DNS": "8.8.8.8"}
        }
    ]

    # Initialize detector with an approved configuration
    approved_configurations = [{"IPAddress": "192.168.1.5"}, {"DNS": "8.8.4.4"}]
    detector = NetworkConfigurationChangesDetector(approved_configurations)

    # Detect unauthorized changes
    unauthorized_changes = detector.detect_unauthorized_changes(sample_logs)
    print("Unauthorized Network Configuration Changes Detected:")
    print(json.dumps(unauthorized_changes, indent=4))
