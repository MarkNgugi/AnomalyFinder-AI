import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta

class AccountChangeAnomalyDetector:
    def __init__(self, window_size=7, threshold=2):
        self.window_size = window_size  # Number of days to consider for anomaly detection
        self.threshold = threshold  # Number of changes above which is considered anomalous
        self.model = IsolationForest(contamination=0.01)  # Model for anomaly detection

    def preprocess_data(self, logs):
        # Convert logs into a DataFrame
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
        
        # Aggregate account changes per day
        daily_changes = df.groupby('date').size().reset_index(name='account_changes')
        
        # Add a column for the number of changes in the previous window
        daily_changes['previous_window_changes'] = daily_changes['account_changes'].rolling(window=self.window_size, min_periods=1).sum()
        
        # Fill NaN values with 0
        daily_changes.fillna(0, inplace=True)
        
        return daily_changes

    def detect_anomalies(self, daily_changes):
        # Standardize the features
        scaler = StandardScaler()
        features = scaler.fit_transform(daily_changes[['previous_window_changes']])
        
        # Fit the model
        self.model.fit(features)
        
        # Predict anomalies
        daily_changes['anomaly'] = self.model.predict(features)
        daily_changes['anomaly'] = daily_changes['anomaly'].apply(lambda x: x == -1)
        
        return daily_changes

    def analyze_logs(self, logs):
        daily_changes = self.preprocess_data(logs)
        anomalies = self.detect_anomalies(daily_changes)
        
        # Filter out the days with anomalies
        anomaly_days = anomalies[anomalies['anomaly']]
        
        return anomaly_days

# Example usage:
if __name__ == "__main__":
    # Example logs
    logs = [
        {'timestamp': '2024-08-25T10:00:00', 'event_type': 'Account Change'},
        {'timestamp': '2024-08-25T12:00:00', 'event_type': 'Account Change'},
        {'timestamp': '2024-08-26T09:00:00', 'event_type': 'Account Change'},
        # Add more logs as needed
    ]

    detector = AccountChangeAnomalyDetector(window_size=7, threshold=2)
    anomalies = detector.analyze_logs(logs)
    
    print("Anomalies detected:")
    print(anomalies)
