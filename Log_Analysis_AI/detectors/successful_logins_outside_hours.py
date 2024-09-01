from datetime import datetime, time

class SuccessfulLoginsOutsideHoursDetector:
    def __init__(self, normal_start_hour=9, normal_end_hour=17):
        """
        Initialize the detector with normal working hours.
        Default is 9 AM to 5 PM.
        """
        self.normal_start_hour = normal_start_hour
        self.normal_end_hour = normal_end_hour

    def is_outside_normal_hours(self, login_time):
        """
        Check if a login time is outside the normal working hours.
        
        Args:
        - login_time (datetime): The timestamp of the login event.
        
        Returns:
        - bool: True if the login is outside normal hours, False otherwise.
        """
        start_time = time(self.normal_start_hour, 0)
        end_time = time(self.normal_end_hour, 0)
        
        return not (start_time <= login_time.time() <= end_time)

    def detect_anomalies(self, logs):
        """
        Detect successful login anomalies outside normal hours from Windows event logs.
        
        Args:
        - logs (list of dict): A list of log entries where each log is a dictionary 
                               containing 'timestamp' and 'event_id' keys.
        
        Returns:
        - list of dict: A list of anomalous login events.
        """
        anomalies = []
        for log in logs:
            # Example log structure: {'timestamp': '2024-09-01 19:23:45', 'event_id': 4624}
            if log['event_id'] == 4624:  # Event ID 4624 indicates a successful login
                login_time = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
                
                if self.is_outside_normal_hours(login_time):
                    anomalies.append(log)

        return anomalies

# Example usage:
if __name__ == "__main__":
    # Sample logs data (replace with actual log data)
    sample_logs = [
        {'timestamp': '2024-09-01 08:30:00', 'event_id': 4624},
        {'timestamp': '2024-09-01 19:23:45', 'event_id': 4624},
        {'timestamp': '2024-09-01 10:15:30', 'event_id': 4624},
        # {'timestamp': '2024-09-01 23:45:12', 'event_id': 4624},
        {'timestamp': '2024-09-01 13:12:55', 'event_id': 4624}
    ]

    # Instantiate the detector with default normal hours (9 AM to 5 PM)
    detector = SuccessfulLoginsOutsideHoursDetector()
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(sample_logs)
    
    # Print the results
    if anomalies:
        print("Anomalous Successful Logins Outside Normal Hours Detected:")
        for anomaly in anomalies:
            print(f"Timestamp: {anomaly['timestamp']}, Event ID: {anomaly['event_id']}")
    else:
        print("No anomalies detected.")
