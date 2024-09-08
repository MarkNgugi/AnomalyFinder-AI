# unusual_outbound_connections.py

import json

# Sample list of known trusted IP addresses or domains
trusted_destinations = [
    "192.168.1.1",  # Example internal IP
    "10.0.0.1",  # Example internal IP
    "trusted-server.example.com",
    "api.trustedservice.com"
]

def is_untrusted_destination(destination, trusted_list):
    """
    Checks if the destination IP or domain is not in the trusted list.
    
    Args:
        destination (str): The IP or domain of the outbound connection.
        trusted_list (list): A list of trusted IPs or domains.
        
    Returns:
        bool: True if the destination is not trusted, False otherwise.
    """
    return destination not in trusted_list

def identify_unusual_outbound_connections(event_logs):
    """
    Identifies unusual outbound connections in the event logs.
    
    Args:
        event_logs (list): A list of dictionaries, each representing a network connection log.
        
    Returns:
        list: A list of unusual outbound connection events.
    """
    unusual_connections = []

    for log in event_logs:
        event_id = log.get("EventID")
        destination = log.get("Destination")
        
        # Check for outbound connections event ID (replace with actual Event ID for outbound connections)
        if event_id == 5156:  # Example Event ID for 'The Windows Filtering Platform has permitted a connection'
            if destination and is_untrusted_destination(destination, trusted_destinations):
                unusual_connections.append(log)

    return unusual_connections

# Sample usage
if __name__ == "__main__":
    # Replace 'sample_logs.json' with the path to your event logs JSON file
    with open('/home/smilex/Documents/DJANGO/AI/Log_Analysis_AI/logs/sample_logs.json', 'r') as file:
        sample_logs = json.load(file)
        
    unusual_connections = identify_unusual_outbound_connections(sample_logs)
    print(json.dumps(unusual_connections, indent=4))
