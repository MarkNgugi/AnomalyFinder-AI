import pandas as pd
from datetime import datetime, timedelta

class AbnormalUserLogoutDetector:
    def __init__(self, log_df, time_window_minutes=30, logout_threshold=5):
        """
        Initializes the AbnormalUserLogoutDetector.

        Args:
            log_df (DataFrame): DataFrame containing Windows Event Logs.
            time_window_minutes (int): Time window in minutes to check for frequent logouts.
            logout_threshold (int): Number of logouts considered abnormal within the time window.
        """
        self.log_df = log_df
        self.time_window = timedelta(minutes=time_window_minutes)
        self.logout_threshold = logout_threshold

    def detect_anomalies(self):
        """
        Detects abnormal user logouts.

        Returns:
            List of dictionaries containing details of abnormal logout activities.
        """
        self.log_df['TimeGenerated'] = pd.to_datetime(self.log_df['TimeGenerated'])
        abnormal_logouts = []

        # Filter logout events (Windows Event ID 4634: An account was logged off)
        logout_events = self.log_df[self.log_df['EventID'] == 4634]

        # Group by user and analyze logout frequency
        grouped = logout_events.groupby('UserName')

        for user, group in grouped:
            group = group.sort_values('TimeGenerated')
            for i in range(len(group) - 1):
                start_time = group.iloc[i]['TimeGenerated']
                end_time = start_time + self.time_window

                # Count logouts within the time window
                logout_count = group[(group['TimeGenerated'] >= start_time) & 
                                     (group['TimeGenerated'] <= end_time)].shape[0]

                if logout_count >= self.logout_threshold:
                    abnormal_logouts.append({
                        'UserName': user,
                        'StartTime': start_time,
                        'EndTime': end_time,
                        'LogoutCount': logout_count
                    })
        
        return abnormal_logouts

# Example usage
if __name__ == "__main__":
    # Sample log data (replace with actual data in practice)
    data = {
        'TimeGenerated': ['2024-09-06 10:01:00', '2024-09-06 10:05:00', '2024-09-06 10:10:00',
                          '2024-09-06 10:15:00', '2024-09-06 10:20:00', '2024-09-06 11:00:00'],
        'EventID': [4634, 4634, 4634, 4634, 4634, 4624],  # 4624 is a successful logon event
        'UserName': ['UserA', 'UserA', 'UserA', 'UserA', 'UserA', 'UserA']
    }

    # Convert to DataFrame
    log_df = pd.DataFrame(data)
    
    # Initialize and run the detector
    detector = AbnormalUserLogoutDetector(log_df)
    anomalies = detector.detect_anomalies()
    print("Detected Anomalies:", anomalies)
