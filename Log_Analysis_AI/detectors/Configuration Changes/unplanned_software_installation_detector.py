import win32evtlog  # pywin32 library to access Windows Event Logs
import datetime

# Define constants
SERVER = 'localhost'  # The name of the computer (local machine)
LOG_TYPE = 'System'   # Event log type
EVENT_ID = 11707      # Event ID for software installation

def fetch_events(server, log_type, event_id, start_time=None):
    """
    Fetch events from the Windows Event Log.
    
    :param server: The name of the server to connect to.
    :param log_type: The type of log to query (e.g., 'System').
    :param event_id: The specific event ID to filter for.
    :param start_time: Optional start time for filtering events.
    :return: List of events.
    """
    events = []
    query = f'*[System[(EventID={event_id})]]'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    handle = win32evtlog.OpenEventLog(server, log_type)
    
    while True:
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        if not records:
            break
        
        for record in records:
            event_time = record.TimeGenerated
            if start_time and event_time < start_time:
                continue
            
            message = win32evtlog.FormatMessage(record, server)
            events.append({
                'time': event_time,
                'source': record.SourceName,
                'event_id': record.EventID,
                'message': message
            })
    
    win32evtlog.CloseEventLog(handle)
    return events

def detect_unplanned_installations(events):
    """
    Detect unplanned or unauthorized software installations from event logs.
    
    :param events: List of events to analyze.
    :return: List of detected unplanned installations.
    """
    detected = []
    
    for event in events:
        if 'Installation' in event['message'] and 'planned' not in event['message'].lower():
            detected.append(event)
    
    return detected

if __name__ == "__main__":
    # Example usage
    start_time = datetime.datetime.now() - datetime.timedelta(days=7)  # Check events from the last 7 days
    events = fetch_events(SERVER, LOG_TYPE, EVENT_ID, start_time)
    unplanned_installations = detect_unplanned_installations(events)
    
    for installation in unplanned_installations:
        print(f"Unplanned Software Installation Detected:")
        print(f"Time: {installation['time']}")
        print(f"Source: {installation['source']}")
        print(f"Event ID: {installation['event_id']}")
        print(f"Message: {installation['message']}")
        print("-" * 40)
