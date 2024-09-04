import json

class UnauthorizedAdminActionsDetector:
    def __init__(self, admin_users):
        """
        Initialize the detector with a list of known administrator accounts.
        :param admin_users: List of usernames that are known administrators.
        """
        self.admin_users = admin_users
    
    def is_administrative_action(self, event_id):
        """
        Check if the event ID corresponds to an administrative action.
        :param event_id: The event ID to check.
        :return: True if it is an administrative action, False otherwise.
        """
        admin_event_ids = {"4672", "4728", "4732", "4648", "4720"}
        return str(event_id) in admin_event_ids
    
    def detect_unauthorized_admin_actions(self, logs):
        """
        Detect unauthorized administrative actions in the provided logs.
        :param logs: List of event logs in JSON format.
        :return: List of detected unauthorized administrative actions.
        """
        unauthorized_actions = []
        for log in logs:
            event_id = log.get("EventID")
            user = log.get("User")
            action_description = log.get("Description")
            
            if self.is_administrative_action(event_id) and user not in self.admin_users:
                unauthorized_actions.append({
                    "User": user,
                    "EventID": event_id,
                    "Description": action_description
                })
        return unauthorized_actions

if __name__ == "__main__":
    # Sample list of known administrator accounts
    admin_users = ["Administrator", "AdminUser1"]

    # Sample logs to test the module
    sample_logs = [
        {"EventID": 4672, "User": "User1", "Description": "Special privileges assigned to new logon"},
        {"EventID": 4728, "User": "AdminUser1", "Description": "A member was added to a security-enabled global group"},
        {"EventID": 4732, "User": "User2", "Description": "A member was added to a security-enabled local group"},
        {"EventID": 4648, "User": "User3", "Description": "A logon was attempted using explicit credentials"},
        {"EventID": 4720, "User": "Administrator", "Description": "A user account was created"},
    ]

    # Initialize the detector
    detector = UnauthorizedAdminActionsDetector(admin_users)

    # Detect unauthorized actions
    unauthorized_actions = detector.detect_unauthorized_admin_actions(sample_logs)

    # Print the results
    print("Unauthorized Administrative Actions Detected:")
    for action in unauthorized_actions:
        print(f"User: {action['User']}, EventID: {action['EventID']}, Description: {action['Description']}")
