import json
import re

def load_logs(file_path):
    """Load logs from a JSON file."""
    with open(file_path, 'r') as file:
        return json.load(file)

def detect_firewall_rule_changes(logs):
    """Detect unplanned changes in firewall rules from logs."""
    changes_detected = []

    for log in logs:
        event_id = log.get('EventID')
        if event_id in ['2004', '2005', '2006']:  # Event IDs for firewall rule changes
            description = log.get('Description', '')
            if re.search(r'(rule|configuration|change|modified|added|removed)', description, re.IGNORECASE):
                changes_detected.append({
                    'EventID': event_id,
                    'Description': description,
                    'Timestamp': log.get('Timestamp')
                })

    return changes_detected

def main():
    # Path to the JSON file containing logs
    file_path = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'
    
    logs = load_logs(file_path)
    changes = detect_firewall_rule_changes(logs)
    
    if changes:
        print("Firewall Rule Changes Detected:")
        for change in changes:
            print(f"Event ID: {change['EventID']}")
            print(f"Description: {change['Description']}")
            print(f"Timestamp: {change['Timestamp']}")
            print()
    else:
        print("No firewall rule changes detected.")

if __name__ == "__main__":
    main()
