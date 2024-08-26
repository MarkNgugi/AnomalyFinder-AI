import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from scipy.stats import zscore
from sklearn.preprocessing import StandardScaler

class FailedLoginDetector:
    def __init__(self, threshold=5, time_window='1h', contamination=0.01):
        self.threshold = threshold
        self.time_window = time_window
        self.contamination = contamination

    def load_data(self, file_path):
        self.df = pd.read_json(file_path)
        print("Columns in DataFrame:", self.df.columns)  # Debugging line
        if 'timestamp' not in self.df.columns or 'event_id' not in self.df.columns:
            raise ValueError("Log file must contain 'timestamp' and 'event_id' columns.")
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        return self.df

    def threshold_based_detection(self):
        # Filter failed login events
        failed_logins = self.df[self.df['event_id'] == 4625]
        failed_logins.set_index('timestamp', inplace=True)
        failed_logins['count'] = failed_logins['event_id'].rolling(window=self.time_window).count()
        detected = failed_logins[failed_logins['count'] > self.threshold]
        return detected

    def z_score_analysis(self):
        # Filter failed login events
        failed_logins = self.df[self.df['event_id'] == 4625]
        failed_logins['hour'] = failed_logins['timestamp'].dt.hour
        failed_logins['day_of_week'] = failed_logins['timestamp'].dt.dayofweek
        
        # Compute Z-scores
        scaler = StandardScaler()
        features = failed_logins[['hour', 'day_of_week']]
        scaled_features = scaler.fit_transform(features)
        failed_logins['z_score'] = zscore(scaled_features, axis=0).mean(axis=1)
        
        # Define anomaly based on Z-score threshold
        z_score_threshold = 3  # Example threshold for Z-score
        anomalies = failed_logins[failed_logins['z_score'].abs() > z_score_threshold]
        return anomalies

    def moving_average_analysis(self):
        # Filter failed login events
        failed_logins = self.df[self.df['event_id'] == 4625]
        failed_logins.set_index('timestamp', inplace=True)
        failed_logins['count'] = failed_logins['event_id'].rolling(window=self.time_window).count()
        
        # Compute Moving Average
        moving_avg = failed_logins['count'].rolling(window=self.time_window).mean()
        detected = failed_logins[failed_logins['count'] > moving_avg + (moving_avg.std() * 2)]
        return detected

    def isolation_forest_detection(self):
        # Feature extraction
        failed_logins = self.df[self.df['event_id'] == 4625]
        failed_logins['hour'] = failed_logins['timestamp'].dt.hour
        failed_logins['day_of_week'] = failed_logins['timestamp'].dt.dayofweek
        
        features = failed_logins[['hour', 'day_of_week']]
        model = IsolationForest(contamination=self.contamination)
        failed_logins['anomaly'] = model.fit_predict(features)
        
        anomalies = failed_logins[failed_logins['anomaly'] == -1]
        return anomalies

    def one_class_svm_detection(self):
        # Feature extraction
        failed_logins = self.df[self.df['event_id'] == 4625]
        failed_logins['hour'] = failed_logins['timestamp'].dt.hour
        failed_logins['day_of_week'] = failed_logins['timestamp'].dt.dayofweek
        
        features = failed_logins[['hour', 'day_of_week']]
        model = OneClassSVM(nu=self.contamination)
        failed_logins['anomaly'] = model.fit_predict(features)
        
        anomalies = failed_logins[failed_logins['anomaly'] == -1]
        return anomalies

    def detect_failures(self, file_path):
        self.load_data(file_path)
        threshold_based = self.threshold_based_detection()
        z_score_based = self.z_score_analysis()
        moving_avg_based = self.moving_average_analysis()
        isolation_forest_based = self.isolation_forest_detection()
        one_class_svm_based = self.one_class_svm_detection()
        
        return {
            'threshold_based': threshold_based,
            'z_score_based': z_score_based,
            'moving_avg_based': moving_avg_based,
            'isolation_forest_based': isolation_forest_based,
            'one_class_svm_based': one_class_svm_based
        }
