import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from io import StringIO

# Sample log data
data = """
Date,Time,EventID,TaskCategory,LogLevel,Keywords,User,Computer,Description
2024-07-30,10:12:30,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:13:45,4625,Logon,Warning,AUDIT_FAILURE,UserB,ComputerA,An account failed to log on.
2024-07-30,10:14:22,4648,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:15:55,4672,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:16:10,4624,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,An account was successfully logged on.
2024-07-30,10:17:23,4648,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:18:45,4625,Logon,Warning,AUDIT_FAILURE,UserD,ComputerA,An account failed to log on.
2024-07-30,10:19:32,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:20:45,4672,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:21:15,4625,Logon,Warning,AUDIT_FAILURE,UserB,ComputerA,An account failed to log on.
2024-07-30,10:22:30,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:23:40,4625,Logon,Warning,AUDIT_FAILURE,UserB,ComputerA,An account failed to log on.
2024-07-30,10:24:50,4688,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A new process has been created.
2024-07-30,10:25:15,4624,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,An account was successfully logged on.
2024-07-30,10:26:22,4648,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:27:55,4672,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:28:10,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:29:45,4625,Logon,Warning,AUDIT_FAILURE,UserB,ComputerA,An account failed to log on.
2024-07-30,10:30:30,4672,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:31:45,4648,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:32:22,4624,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,An account was successfully logged on.
2024-07-30,10:33:45,4625,Logon,Warning,AUDIT_FAILURE,UserD,ComputerA,An account failed to log on.
2024-07-30,10:34:50,4648,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:35:15,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:36:22,4648,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:37:55,4672,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:38:10,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:39:45,4625,Logon,Warning,AUDIT_FAILURE,UserB,ComputerA,An account failed to log on.
2024-07-30,10:40:30,4672,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:41:45,4648,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:42:22,4624,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,An account was successfully logged on.
2024-07-30,10:43:45,4625,Logon,Warning,AUDIT_FAILURE,UserD,ComputerA,An account failed to log on.
2024-07-30,10:44:50,4688,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A new process has been created.
2024-07-30,10:45:15,4624,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,An account was successfully logged on.
2024-07-30,10:46:22,4648,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,A logon was attempted using explicit credentials.
2024-07-30,10:47:55,4672,Logon,Information,AUDIT_SUCCESS,UserC,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:48:10,4624,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,An account was successfully logged on.
2024-07-30,10:49:45,4625,Logon,Warning,AUDIT_FAILURE,UserB,ComputerA,An account failed to log on.
2024-07-30,10:50:30,4672,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,Special privileges assigned to new logon.
2024-07-30,10:51:45,4648,Logon,Information,AUDIT_SUCCESS,UserA,ComputerA,A logon was attempted using explicit credentials.
"""

# Load data into DataFrame
df = pd.read_csv(StringIO(data))

# Combine Description and LogLevel into a single feature for vectorization
df['Combined'] = df['Description'] + ' ' + df['LogLevel']

# Vectorize the Combined feature
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['Combined'])

# Reduce dimensions for anomaly detection
pca = PCA(n_components=2)
X_reduced = pca.fit_transform(X.toarray())

# Initialize Isolation Forest
iso_forest = IsolationForest(contamination=0.1)
iso_forest.fit(X_reduced)

# Predict anomalies
df['Anomaly'] = iso_forest.predict(X_reduced)
df['Anomaly'] = df['Anomaly'].map({-1: 'Anomaly', 1: 'Normal'})

# Classify logs into Alerts, Anomalies, or Normal
# Define Alerts based on LogLevel
alert_levels = ['Warning']  # Define levels that you consider as alerts
df['Alert'] = df['LogLevel'].apply(lambda x: 'Alert' if x in alert_levels else 'Normal')

# Final classification combining Anomaly and Alert
def classify_log(row):
    if row['Anomaly'] == 'Anomaly':
        return 'Anomaly'
    elif row['Alert'] == 'Alert':
        return 'Alert'
    else:
        return 'Normal'

df['Classification'] = df.apply(classify_log, axis=1)

# Display results
print(df[['Date', 'Time', 'Description', 'LogLevel', 'Anomaly', 'Alert', 'Classification']])
