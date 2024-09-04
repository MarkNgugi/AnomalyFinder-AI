import json
import pandas as pd

class GroupMembershipChangesDetector:
    def __init__(self, logs_file):
        """
        Initialize the detector with a JSON log file.
        :param logs_file: Path to the JSON log file containing Windows event logs.
        """
        self.logs_file = logs_file
        self.df = self.load_logs()

    def load_logs(self):
        """
        Load logs from a JSON file into a DataFrame.
        :return: DataFrame containing the logs.
        """
        with open(self.logs_file, 'r') as file:
            logs = json.load(file)
        return pd.DataFrame(logs)

    def detect_group_membership_changes(self):
        """
        Detect unexpected changes in user group memberships from the logs.
        :return: DataFrame with detected anomalies.
        """
        # Filter for event IDs related to group membership changes
        group_membership_events = self.df[self.df['EventID'].isin([4728, 4732, 4729, 4733])]
        
        # Define the criteria for unexpected changes
        anomalies = group_membership_events[(group_membership_events['EventID'] == 4728) | 
                                             (group_membership_events['EventID'] == 4732)]
        
        return anomalies

    def display_anomalies(self, anomalies):
        """
        Display the detected anomalies.
        :param anomalies: DataFrame containing detected anomalies.
        """
        if not anomalies.empty:
            print("Detected Anomalies in Group Membership Changes:")
            print(anomalies[['TimeCreated', 'EventID', 'Message']])
        else:
            print("No anomalies detected.")

if __name__ == "__main__":
    # Path to the JSON file containing the Windows event logs
    logs_file_path = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    # Create an instance of the detector
    detector = GroupMembershipChangesDetector(logs_file_path)
    
    # Detect group membership changes
    anomalies = detector.detect_group_membership_changes()
    
    # Display the detected anomalies
    detector.display_anomalies(anomalies)
