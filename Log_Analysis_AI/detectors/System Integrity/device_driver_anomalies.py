import json

def load_logs(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def identify_driver_errors(logs):
    driver_error_events = []
    for log in logs:
        if log.get('EventID') in [41, 56, 117, 201, 301]:  # Example event IDs for driver-related issues
            driver_error_events.append(log)
    return driver_error_events

def main():
    log_file = '/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json'  # Path to your JSON log file
    logs = load_logs(log_file)
    errors = identify_driver_errors(logs)
    
    if errors:
        print("Driver-related errors detected:")
        for error in errors:
            print(f"Time: {error.get('TimeGenerated')}, Event ID: {error.get('EventID')}, Message: {error.get('Message')}")
    else:
        print("No driver-related errors detected.")

if __name__ == "__main__":
    main()
