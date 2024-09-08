import json

class DNSResolutionFailureDetector:
    def __init__(self, threshold=5):
        """
        Initialize the detector with a threshold for anomaly detection.

        Args:
        threshold (int): The number of DNS resolution failures considered anomalous.
        """
        self.threshold = threshold

    def detect(self, logs):
        """
        Detect DNS resolution failures or unusual DNS requests in logs.

        Args:
        logs (list): List of event logs in JSON format.

        Returns:
        list: List of detected anomalies.
        """
        dns_failure_events = []
        event_id_1014 = "1014"  # Windows DNS client event ID for DNS resolution failures
        
        for log in logs:
            if log.get("EventID") == event_id_1014:
                dns_failure_events.append(log)
        
        # Determine if the number of DNS failures exceeds the threshold
        if len(dns_failure_events) > self.threshold:
            print(f"Anomaly detected: {len(dns_failure_events)} DNS resolution failures.")
            return dns_failure_events
        
        return []

if __name__ == "__main__":
    # Sample logs for testing
    sample_logs = [
        {"EventID": "1014", "Source": "DNS Client Events", "Message": "Name resolution for the name www.example.com timed out after none of the configured DNS servers responded."},
        {"EventID": "1014", "Source": "DNS Client Events", "Message": "Name resolution for the name api.example.org timed out after none of the configured DNS servers responded."},
        {"EventID": "1014", "Source": "DNS Client Events", "Message": "Name resolution for the name mail.example.net timed out after none of the configured DNS servers responded."},
        {"EventID": "4624", "Source": "Security", "Message": "An account was successfully logged on."},
        {"EventID": "1014", "Source": "DNS Client Events", "Message": "Name resolution for the name ftp.example.com timed out after none of the configured DNS servers responded."},
        {"EventID": "1014", "Source": "DNS Client Events", "Message": "Name resolution for the name intranet.example.local timed out after none of the configured DNS servers responded."},
    ]

    # Initialize the detector
    detector = DNSResolutionFailureDetector(threshold=3)
    
    # Detect anomalies
    anomalies = detector.detect(sample_logs)
    
    # Output the anomalies
    if anomalies:
        print("Detected DNS Resolution Failures:")
        for anomaly in anomalies:
            print(json.dumps(anomaly, indent=4))
    else:
        print("No DNS Resolution Failures Detected.")
