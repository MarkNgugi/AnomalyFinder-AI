import json
from typing import List

def load_logs(file_path: str) -> List[dict]:
    """ Load JSON logs from a file. """
    with open(file_path, 'r') as file:
        logs = json.load(file)
    return logs

def detect_group_policy_alterations(logs: List[dict]) -> List[dict]:
    """ Detect unexpected changes to group policy settings. """
    detected_changes = []
    
    for log in logs:
        event_id = log.get('EventID')
        if event_id in [4739, 4719, 4670]:  # Event IDs related to Group Policy changes
            detected_changes.append(log)
    
    return detected_changes

def main(log_file: str):
    logs = load_logs(log_file)
    alterations = detect_group_policy_alterations(logs)
    
    if alterations:
        print(f"Detected {len(alterations)} group policy alterations:")
        for alteration in alterations:
            print(alteration)
    else:
        print("No group policy alterations detected.")

if __name__ == "__main__":
    # Replace 'sample_logs.json' with the path to your log file
    main('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json')
