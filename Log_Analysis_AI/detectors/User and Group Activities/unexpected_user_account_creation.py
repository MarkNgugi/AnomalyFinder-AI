import re
from datetime import datetime

def parse_event_log(log_line):
    """
    Parses a log line to extract the relevant information.
    Assumes the log format has a certain structure.
    """
    try:
        # Example log parsing, adjust this depending on actual log format
        event_time = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", log_line).group(1)
        event_id = re.search(r"Event ID: (\d+)", log_line).group(1)
        account_name = re.search(r"Account Name: (\w+)", log_line).group(1)
        created_by = re.search(r"Created By: (\w+)", log_line).group(1)
        
        return {
            "timestamp": datetime.strptime(event_time, "%Y-%m-%d %H:%M:%S"),
            "event_id": int(event_id),
            "account_name": account_name,
            "created_by": created_by
        }
    except AttributeError:
        return None

def is_unexpected_user_creation(log, authorized_creators=None, time_window=None):
    """
    Checks if the user account creation event is unexpected based on criteria.
    """
    authorized_creators = authorized_creators or ["Admin", "Administrator"]
    time_window = time_window or (0, 6)  # example: unusual hours between 0-6 AM

    # Ensure it's the correct event ID for account creation (4720)
    if log["event_id"] != 4720:
        return False

    # Check if the account was created by an unauthorized user
    if log["created_by"] not in authorized_creators:
        return True
    
    # Check if the creation time is within the defined "unusual" time window
    if log["timestamp"].hour >= time_window[0] and log["timestamp"].hour <= time_window[1]:
        return True
    
    return False

def analyze_logs(logs):
    """
    Analyzes a list of logs and identifies unexpected user account creations.
    """
    unexpected_creations = []
    for log_line in logs:
        log = parse_event_log(log_line)
        if log and is_unexpected_user_creation(log):
            unexpected_creations.append(log)
    
    return unexpected_creations


# Example usage
if __name__ == "__main__":
    # Sample log lines
    sample_logs = [
        "2024-09-06 02:30:45 Event ID: 4720 Account Name: new_user Created By: guest",
        "2024-09-06 14:10:30 Event ID: 4720 Account Name: temp_user Created By: Admin",
        "2024-09-06 03:15:00 Event ID: 4720 Account Name: service_user Created By: system",
    ]
    
    # Analyze the logs
    unexpected_creations = analyze_logs(sample_logs)
    print("Unexpected User Account Creations:")
    for entry in unexpected_creations:
        print(entry)
