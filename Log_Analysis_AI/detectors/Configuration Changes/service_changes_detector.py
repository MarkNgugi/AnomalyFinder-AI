import json
import re
from typing import List, Dict

class ServiceChangesDetector:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path

    def load_logs(self) -> List[Dict]:
        """Load and parse the JSON log file."""
        with open(self.log_file_path, 'r') as file:
            logs = json.load(file)
        return logs

    def detect_service_changes(self, logs: List[Dict]) -> List[Dict]:
        """Detect modifications to system services."""
        detected_changes = []

        for log in logs:
            event_id = log.get('EventID')
            if event_id in ['7040', '7045']:
                detected_changes.append(log)

        return detected_changes

    def analyze_changes(self, changes: List[Dict]) -> None:
        """Analyze detected changes and print summary."""
        if not changes:
            print("No significant changes to system services detected.")
            return
        
        for change in changes:
            event_id = change.get('EventID')
            message = change.get('Message', 'No details available')
            timestamp = change.get('Timestamp', 'Unknown time')
            print(f"Detected Change - Event ID: {event_id}, Time: {timestamp}")
            print(f"Details: {message}\n")

    def run(self) -> None:
        """Run the detector on the provided log file."""
        logs = self.load_logs()
        changes = self.detect_service_changes(logs)
        self.analyze_changes(changes)

# Example usage
if __name__ == "__main__":
    detector = ServiceChangesDetector('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json')
    detector.run()
