import json
from typing import List, Dict

# Whitelist of known and authorized IP addresses or network ranges
AUTHORIZED_IPS = {
    "192.168.0.0/24",  # Example internal network
    "10.0.0.0/8",      # Example internal network
    "203.0.113.5",     # Example external authorized IP
}

def is_ip_authorized(ip: str) -> bool:
    """
    Check if an IP address is in the authorized IP ranges.
    """
    from ipaddress import ip_address, ip_network

    try:
        ip_obj = ip_address(ip)
        for network in AUTHORIZED_IPS:
            if ip_obj in ip_network(network):
                return True
    except ValueError:
        pass  # Invalid IP address format
    return False

def identify_unusual_network_connections(logs: List[Dict]) -> List[Dict]:
    """
    Identify unusual network connections from event logs.
    
    Args:
    - logs: A list of dictionaries representing Windows event logs.

    Returns:
    - A list of dictionaries representing the identified unusual network connection logs.
    """
    unusual_connections = []

    for log in logs:
        event_id = log.get("EventID")
        ip_address = log.get("DestinationAddress")
        
        # Focus on specific network connection events (Event ID 5156: Permitted connections)
        if event_id == 5156:
            if ip_address and not is_ip_authorized(ip_address):
                unusual_connections.append(log)
                
    return unusual_connections

def main():
    # Sample log data (In practice, this would be read from a log file or API)
    logs = [
        {
            "EventID": 5156,
            "SourceAddress": "192.168.1.10",
            "DestinationAddress": "203.0.113.5",  # Authorized IP
            "Message": "The Windows Filtering Platform has permitted a connection.",
        },
        {
            "EventID": 5156,
            "SourceAddress": "192.168.1.10",
            "DestinationAddress": "8.8.8.8",  # Unauthorized IP
            "Message": "The Windows Filtering Platform has permitted a connection.",
        },
        {
            "EventID": 5157,
            "SourceAddress": "192.168.1.10",
            "DestinationAddress": "10.0.0.5",  # Authorized IP
            "Message": "The Windows Filtering Platform has blocked a connection.",
        },
        {
            "EventID": 5156,
            "SourceAddress": "192.168.1.10",
            "DestinationAddress": "203.0.114.8",  # Unauthorized IP
            "Message": "The Windows Filtering Platform has permitted a connection.",
        }
    ]

    # Identify unusual network connections
    unusual_connections = identify_unusual_network_connections(logs)
    
    if unusual_connections:
        print("Unusual Network Connections Detected:")
        for conn in unusual_connections:
            print(f"EventID: {conn['EventID']}, Source: {conn['SourceAddress']}, Destination: {conn['DestinationAddress']}")
    else:
        print("No unusual network connections detected.")

if __name__ == "__main__":
    main()
