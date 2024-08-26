import pandas as pd

def load_log_file(file_path):
    """
    Load and preprocess the log file.

    :param file_path: Path to the log file.
    :return: DataFrame containing the parsed log data.
    """
    # Example for JSON logs; adjust if using a different format
    df = pd.read_json(file_path)
    
    # Ensure columns are present
    if 'timestamp' not in df.columns or 'event_id' not in df.columns:
        raise ValueError("Log file must contain 'timestamp' and 'event_id' columns.")
    
    return df
