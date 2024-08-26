from detectors.failed_login_detector import FailedLoginDetector
from utils.log_parser import load_log_file

def main():
    # Path to your log file
    log_file_path = 'logs/sample_logs.json'
    
    # Initialize the detector
    detector = FailedLoginDetector()
    
    # Load the log data
    df = load_log_file(log_file_path)
    
    # Save the DataFrame to a file to debug
    df.to_csv('logs/debug_log_file.csv', index=False)  # Debugging line

    # Detect failed logins
    results = detector.detect_failures(log_file_path)
    
    # Print or handle the results
    print("Threshold-Based Detection Results:")
    print(results['threshold_based'])
    
    print("\nZ-Score Based Detection Results:")
    print(results['z_score_based'])
    
    print("\nMoving Average Based Detection Results:")
    print(results['moving_avg_based'])
    
    print("\nIsolation Forest Detection Results:")
    print(results['isolation_forest_based'])
    
    print("\nOne-Class SVM Detection Results:")
    print(results['one_class_svm_based'])

if __name__ == "__main__":
    main()
