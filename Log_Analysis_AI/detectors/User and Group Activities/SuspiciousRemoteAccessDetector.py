import pandas as pd

class SuspiciousRemoteAccessDetector:
    def __init__(self, trusted_ips):
        """
        Initialize the module with a list of trusted IP addresses.
        
        Parameters:
        trusted_ips (list): A list of trusted IP addresses for comparison.
        """
        self.trusted_ips = set(trusted_ips)

    def detect_suspicious_access(self, log_data):
        """
        Detects suspicious remote access attempts from unfamiliar or untrusted sources.
        
        Parameters:
        log_data (DataFrame): DataFrame containing event log data.

        Returns:
        DataFrame: DataFrame containing suspicious remote access events.
        """
        # Filter events for remote access (Event ID 4624 for successful logon and Event ID 4648 for explicit logon)
        remote_access_events = log_data[
            (log_data['EventID'].isin([4624, 4648])) &
            (log_data['LogonType'].isin([3, 10]))  # 3=Network logon, 10=RemoteInteractive (RDP)
        ]

        # Filter out events from trusted IPs
        suspicious_events = remote_access_events[
            ~remote_access_events['SourceIP'].isin(self.trusted_ips)
        ]

        return suspicious_events

# Sample usage:
if __name__ == "__main__":
    # Define a list of trusted IP addresses
    trusted_ips = ["192.168.1.1", "10.0.0.5", "172.16.0.2"]

    # Sample log data in CSV format
    sample_log_data = {
        "EventID": [4624, 4624, 4648, 4624],
        "LogonType": [3, 10, 3, 10],
        "SourceIP": ["203.0.113.5", "192.168.1.1", "198.51.100.10", "10.0.0.5"],
        "Timestamp": ["2024-09-06 10:05:23", "2024-09-06 10:10:30", "2024-09-06 10:12:45", "2024-09-06 10:15:00"]
    }

    # Convert sample log data to DataFrame
    log_df = pd.DataFrame(sample_log_data)

    # Initialize detector with trusted IPs
    detector = SuspiciousRemoteAccessDetector(trusted_ips)

    # Detect suspicious remote access
    suspicious_access = detector.detect_suspicious_access(log_df)
    print("Suspicious Remote Access Attempts:")
    print(suspicious_access)
