import win32evtlog
import win32evtlogutil
import datetime

class FailedNetworkConnectionsModule:
    """
    Module to detect failed or refused network connection attempts from Windows Event Logs.
    """
    
    def __init__(self, server='localhost', log_type='System'):
        self.server = server  # Server to connect to for logs (use 'localhost' for the local machine)
        self.log_type = log_type  # Log type (System log in this case)
        self.event_ids = [4227, 4231]  # Event IDs related to TCPIP connection failures
        self.time_delta_minutes = 10  # Time window to analyze recent events (e.g., last 10 minutes)
        self.threshold = 5  # Threshold for the number of failed attempts to consider as anomaly
    
    def read_event_logs(self):
        """
        Reads the event logs and filters based on specific Event IDs.
        """
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        handle = win32evtlog.OpenEventLog(self.server, self.log_type)
        
        events = []
        current_time = datetime.datetime.now()
        time_delta = datetime.timedelta(minutes=self.time_delta_minutes)
        
        while True:
            event_list = win32evtlog.ReadEventLog(handle, flags, 0)
            if not event_list:
                break
            
            for event in event_list:
                event_time = event.TimeGenerated
                if current_time - event_time > time_delta:
                    continue  # Only analyze events within the specified time window
                
                if event.EventID in self.event_ids:
                    event_data = {
                        'EventID': event.EventID,
                        'TimeGenerated': event.TimeGenerated,
                        'SourceName': event.SourceName,
                        'EventCategory': event.EventCategory,
                        'EventType': event.EventType,
                        'EventDescription': win32evtlogutil.SafeFormatMessage(event, self.log_type)
                    }
                    events.append(event_data)
        
        win32evtlog.CloseEventLog(handle)
        return events

    def detect_anomalies(self):
        """
        Detects anomalies based on the number of failed network connection attempts.
        """
        events = self.read_event_logs()
        if len(events) > self.threshold:
            print(f"Anomaly Detected: {len(events)} failed network connection attempts in the last {self.time_delta_minutes} minutes.")
            for event in events:
                print(f"EventID: {event['EventID']} | Time: {event['TimeGenerated']} | Description: {event['EventDescription']}")
        else:
            print("No anomaly detected.")
    
# Usage
if __name__ == "__main__":
    module = FailedNetworkConnectionsModule()
    module.detect_anomalies()
