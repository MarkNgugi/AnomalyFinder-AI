import json
from datetime import datetime, timedelta
from collections import Counter
from typing import List, Dict, Any
#print the first expression



print ('STARTING THE ANALYSIS PROCESS')
# Load Logs Function
def load_logs(filepath: str) -> List[Dict[str, Any]]:
    """Load logs from a JSON file."""
    with open(filepath, 'r') as file:
        return json.load(file)

# Sliding Window with Count - Brute Force Attack
def detect_brute_force(logs: List[Dict[str, Any]], time_window_minutes: int = 5, attempt_threshold: int = 10) -> List[Dict[str, Any]]:
    user_attempts = {}
    for log in logs:
        timestamp = datetime.strptime(log["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        account_name = log["AccountName"]
        if account_name not in user_attempts:
            user_attempts[account_name] = []
        user_attempts[account_name].append(timestamp)
    
    anomalies = []
    for account, attempts in user_attempts.items():
        attempts.sort()
        window_start = 0
        for i in range(len(attempts)):
            while attempts[i] - attempts[window_start] > timedelta(minutes=time_window_minutes):
                window_start += 1
            if i - window_start + 1 > attempt_threshold:
                anomalies.extend(log for log in logs if log["AccountName"] == account and datetime.strptime(log["Timestamp"], "%Y-%m-%dT%H:%M:%SZ") in attempts[window_start:i+1])
    
    return anomalies

# Count Aggregation with Thresholding - Spray Attack
def detect_spray_attack(logs: List[Dict[str, Any]], user_threshold: int = 3) -> List[Dict[str, Any]]:
    ip_user_counts = Counter((log["SourceIP"], log["AccountName"]) for log in logs)
    ip_counts = Counter(log["SourceIP"] for log in logs)
    
    anomalies = []
    for (ip, _), count in ip_user_counts.items():
        if count >= user_threshold:
            anomalies.extend(log for log in logs if log["SourceIP"] == ip)
    
    return anomalies

# Frequency Analysis - Unusual Logon Types
def detect_unusual_logon_types(logs: List[Dict[str, Any]], logon_types: List[int]) -> List[Dict[str, Any]]:
    type_counts = Counter(log["LogonType"] for log in logs)
    anomalies = [log for log in logs if log["LogonType"] in logon_types]
    
    return anomalies

# Rule-Based Detection - Invalid or Disabled Account States
def detect_invalid_account_states(logs: List[Dict[str, Any]], invalid_states: List[str]) -> List[Dict[str, Any]]:
    return [log for log in logs if log["FailureReason"] in invalid_states]

# Time-Based Filtering with Histogram - Failed Logins Outside Normal Business Hours
def detect_failed_logins_outside_hours(logs: List[Dict[str, Any]], start_hour: int = 8, end_hour: int = 18) -> List[Dict[str, Any]]:
    anomalies = []
    for log in logs:
        timestamp = datetime.strptime(log["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        if timestamp.hour < start_hour or timestamp.hour >= end_hour:
            anomalies.append(log)
    
    return anomalies

# Threshold-Based Counting - High Frequency from Single IP
def detect_high_frequency_ip(logs: List[Dict[str, Any]], frequency_threshold: int = 100, time_frame_minutes: int = 30) -> List[Dict[str, Any]]:
    ip_counts = Counter(log["SourceIP"] for log in logs)
    anomalies = [log for log in logs if ip_counts[log["SourceIP"]] > frequency_threshold]
    
    return anomalies

# Sequential Pattern Detection - Sequential Failed Logins
def detect_sequential_failed_logins(logs: List[Dict[str, Any]], time_frame_seconds: int = 10) -> List[Dict[str, Any]]:
    ip_user_attempts = {}
    for log in logs:
        timestamp = datetime.strptime(log["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        ip_user = (log["SourceIP"], log["AccountName"])
        if ip_user not in ip_user_attempts:
            ip_user_attempts[ip_user] = []
        ip_user_attempts[ip_user].append(timestamp)
    
    anomalies = []
    for (ip, user), attempts in ip_user_attempts.items():
        attempts.sort()
        for i in range(len(attempts) - 1):
            if (attempts[i+1] - attempts[i]).total_seconds() <= time_frame_seconds:
                anomalies.extend(log for log in logs if log["SourceIP"] == ip and log["AccountName"] == user)
    
    return anomalies

# Pattern Matching with Common Username List - Common Attack Vectors in Usernames
def detect_common_username_attempts(logs: List[Dict[str, Any]], common_usernames: List[str]) -> List[Dict[str, Any]]:
    return [log for log in logs if log["AccountName"] in common_usernames]

# Geolocation Anomaly Detection - Geographic Location Anomalies
def detect_geographic_anomalies(logs: List[Dict[str, Any]], normal_locations: List[str]) -> List[Dict[str, Any]]:
    anomalies = []
    for log in logs:
        ip_location = log["SourceIP"]  # Placeholder for IP geolocation lookup
        if ip_location not in normal_locations:
            anomalies.append(log)
    
    return anomalies

# Event Correlation - Recurrent Failed Logins Followed by Successful Login
def detect_recurrent_failures_followed_by_success(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    successes = {log["SourceIP"]: log for log in logs if log["EventID"] == "Success"}
    failures = [log for log in logs if log["EventID"] == "Failure"]
    
    anomalies = []
    for failure in failures:
        ip = failure["SourceIP"]
        if ip in successes:
            last_failure_time = datetime.strptime(failure["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            success_time = datetime.strptime(successes[ip]["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            if (success_time - last_failure_time).total_seconds() < 300:  # 5 minutes window
                anomalies.append(failure)
    
    return anomalies

# Main Function to Run All Detection Methods
def main(filepath: str):
    logs = load_logs(filepath)
    
    # Brute Force Attack
    anomalies_brute_force = detect_brute_force(logs)
    print(f"Brute Force Anomalies Detected: {len(anomalies_brute_force)}")
    print("Brute Force Anomalies:")
    for log in anomalies_brute_force:
        print(log)
    
    # Spray Attack
    anomalies_spray_attack = detect_spray_attack(logs)
    print(f"Spray Attack Anomalies Detected: {len(anomalies_spray_attack)}")
    print("Spray Attack Anomalies:")
    for log in anomalies_spray_attack:
        print(log)
    
    # Unusual Logon Types
    anomalies_unusual_logon = detect_unusual_logon_types(logs, [10, 3])  # Example LogonTypes
    print(f"Unusual Logon Types Anomalies Detected: {len(anomalies_unusual_logon)}")
    print("Unusual Logon Types Anomalies:")
    for log in anomalies_unusual_logon:
        print(log)
    
    # Invalid Account States
    anomalies_invalid_states = detect_invalid_account_states(logs, ["AccountDisabled", "AccountExpired", "AccountLockedOut", "InvalidUserName"])
    print(f"Invalid Account States Anomalies Detected: {len(anomalies_invalid_states)}")
    print("Invalid Account States Anomalies:")
    for log in anomalies_invalid_states:
        print(log)
    
    # Failed Logins Outside Normal Hours
    anomalies_outside_hours = detect_failed_logins_outside_hours(logs)
    print(f"Failed Logins Outside Normal Hours Detected: {len(anomalies_outside_hours)}")
    print("Failed Logins Outside Normal Hours:")
    for log in anomalies_outside_hours:
        print(log)
    
    # High Frequency from Single IP
    anomalies_high_frequency_ip = detect_high_frequency_ip(logs)
    print(f"High Frequency from Single IP Detected: {len(anomalies_high_frequency_ip)}")
    print("High Frequency from Single IP Anomalies:")
    for log in anomalies_high_frequency_ip:
        print(log)
    
    # Sequential Failed Logins
    anomalies_sequential_logins = detect_sequential_failed_logins(logs)
    print(f"Sequential Failed Logins Detected: {len(anomalies_sequential_logins)}")
    print("Sequential Failed Logins Anomalies:")
    for log in anomalies_sequential_logins:
        print(log)
    
    # Common Username Attempts
    anomalies_common_usernames = detect_common_username_attempts(logs, ["admin", "administrator", "root"])
    print(f"Common Username Attempts Detected: {len(anomalies_common_usernames)}")
    print("Common Username Attempts Anomalies:")
    for log in anomalies_common_usernames:
        print(log)
    
    # Geographic Location Anomalies
    anomalies_geographic = detect_geographic_anomalies(logs, ["US", "CA"])  # Example locations
    print(f"Geographic Location Anomalies Detected: {len(anomalies_geographic)}")
    print("Geographic Location Anomalies:")
    for log in anomalies_geographic:
        print(log)
    
    # Recurrent Failures Followed by Success
    anomalies_recurrent_failures = detect_recurrent_failures_followed_by_success(logs)
    print(f"Recurrent Failures Followed by Success Detected: {len(anomalies_recurrent_failures)}")
    print("Recurrent Failures Followed by Success Anomalies:")
    for log in anomalies_recurrent_failures:
        print(log)

if __name__ == "__main__":
    main('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json')
