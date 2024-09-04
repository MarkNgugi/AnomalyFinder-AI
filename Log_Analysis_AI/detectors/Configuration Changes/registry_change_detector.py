import pandas as pd
import re

def load_logs(file_path):
    """
    Load logs from the specified file path.
    Supports CSV and JSON formats.
    """
    if file_path.endswith('.csv'):
        return pd.read_csv(file_path)
    elif file_path.endswith('.json'):
        return pd.read_json(file_path)
    else:
        raise ValueError("Unsupported file format. Please use CSV or JSON.")

def detect_registry_changes(logs):
    """
    Detect unauthorized registry changes in the logs.
    """
    # Example regex pattern to match registry modification events
    registry_change_pattern = re.compile(r"(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\.*")

    # Filter logs based on event ID related to registry modifications
    # Event ID 4657 indicates that a registry value has been modified
    registry_changes = logs[logs['EventID'] == 4657]

    # Further filter logs where the registry path matches the pattern
    unauthorized_changes = registry_changes[registry_changes['RegistryPath'].str.contains(registry_change_pattern, na=False)]

    return unauthorized_changes

def main(file_path):
    logs = load_logs(file_path)
    unauthorized_changes = detect_registry_changes(logs)
    
    if not unauthorized_changes.empty:
        print("Unauthorized registry changes detected:")
        print(unauthorized_changes)
    else:
        print("No unauthorized registry changes detected.")

if __name__ == "__main__":
    # Replace 'sample_logs.json' with the path to your log file
    main('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json')
