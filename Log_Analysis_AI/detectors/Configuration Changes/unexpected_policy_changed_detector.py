import pandas as pd
import re

# Define event IDs related to security policy changes
SECURITY_POLICY_CHANGE_EVENT_IDS = {
    4739,  # A domain policy was changed
    4740,  # A user account was locked out
    4720,  # A user account was created
    4722,  # A user account was enabled
    4725,  # A user account was disabled
    4726,  # A user account was deleted
    4738,  # A user account was changed
    4719,  # System audit policy was changed
}

def detect_policy_changes(logs_df):
    """
    Detect unexpected changes in security policies from Windows event logs.
    
    Args:
        logs_df (pd.DataFrame): DataFrame containing event logs with columns 'EventID', 'Message'.
    
    Returns:
        pd.DataFrame: DataFrame containing detected anomalies.
    """
    # Filter logs for events related to security policy changes
    policy_changes_df = logs_df[logs_df['EventID'].astype(int).isin(SECURITY_POLICY_CHANGE_EVENT_IDS)]
    
    # Create a column for anomalies
    policy_changes_df['Anomaly'] = policy_changes_df['Message'].apply(
        lambda x: 'unauthorized' in x.lower() or re.search(r'changed|modified|adjusted', x, re.IGNORECASE) is not None
    )
    
    # Filter out anomalies
    detected_anomalies = policy_changes_df[policy_changes_df['Anomaly']]
    
    return detected_anomalies

# Sample usage
if __name__ == "__main__":
    # Sample logs in DataFrame format
    sample_logs = pd.DataFrame({
        'EventID': [4739, 4725, 4719, 4738, 4740],
        'Message': [
            'A domain policy was changed by user X',
            'User account Y was disabled',
            'System audit policy was changed by user Z',
            'User account Z was modified',
            'User account A was locked out'
        ]
    })

    detected_anomalies = detect_policy_changes(sample_logs)
    print(detected_anomalies)
