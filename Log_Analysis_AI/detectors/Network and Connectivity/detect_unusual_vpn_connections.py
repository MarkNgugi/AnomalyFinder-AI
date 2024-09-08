# detect_unusual_vpn_connections.py

import json

class VPNConnectionDetector:
    def __init__(self, known_vpn_services=None):
        # List of known or expected VPN services and IPs
        if known_vpn_services is None:
            known_vpn_services = ["vpnservice1", "vpnservice2", "vpnservice3"]
        self.known_vpn_services = known_vpn_services

    def is_unusual_vpn_connection(self, log_entry):
        """
        Determines if a given log entry is an unusual VPN connection.
        
        :param log_entry: A dictionary containing event log data.
        :return: True if the connection is unusual, False otherwise.
        """
        # Check if the log entry contains VPN connection information
        if log_entry.get("EventID") == 20225:  # EventID 20225 is for RAS/VPN connections
            vpn_service = log_entry.get("VPNService")
            if vpn_service and vpn_service not in self.known_vpn_services:
                return True  # Unusual VPN connection
        return False

    def analyze_logs(self, logs):
        """
        Analyzes a list of logs to detect unusual VPN connections.
        
        :param logs: A list of dictionaries containing event log data.
        :return: A list of unusual VPN connection logs.
        """
        unusual_vpn_logs = []
        for log in logs:
            if self.is_unusual_vpn_connection(log):
                unusual_vpn_logs.append(log)
        return unusual_vpn_logs

# Example usage
if __name__ == "__main__":
    # Sample logs in JSON format
    sample_logs = [
        {"EventID": 20225, "VPNService": "vpnservice1", "User": "UserA", "SourceIP": "192.168.1.10"},
        {"EventID": 20225, "VPNService": "vpnservice_unknown", "User": "UserB", "SourceIP": "192.168.1.11"},
        {"EventID": 12345, "VPNService": "vpnservice3", "User": "UserC", "SourceIP": "192.168.1.12"},
        {"EventID": 20225, "VPNService": "vpnservice4", "User": "UserD", "SourceIP": "192.168.1.13"}
    ]

    detector = VPNConnectionDetector()
    unusual_connections = detector.analyze_logs(sample_logs)

    # Print out unusual VPN connections
    print("Unusual VPN Connections Detected:")
    print(json.dumps(unusual_connections, indent=4))
