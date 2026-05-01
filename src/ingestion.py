import pandas as pd
import json
import os

class LogIngestor:
    def __init__(self, file_path):
        """
        Initialize the LogIngestor with the path to the Sysmon logs JSON file.
        """
        self.file_path = file_path

    def load_logs(self):
        """
        Loads the JSON log file and returns a pandas DataFrame.
        Expected fields: EventID, Timestamp, ProcessName, CommandLine, ParentProcessName
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Log file not found at {self.file_path}")

        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Assuming data is a list of log dictionaries
            df = pd.DataFrame(data)
            
            # Basic validation
            required_cols = ['EventID', 'Timestamp', 'ProcessName', 'CommandLine', 'ParentProcessName']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                print(f"Warning: Missing expected columns: {missing_cols}")

            # Ensure timestamp is datetime
            if 'Timestamp' in df.columns:
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])

            # Fill NaNs in text fields
            text_cols = ['ProcessName', 'CommandLine', 'ParentProcessName']
            for col in text_cols:
                if col in df.columns:
                    df[col] = df[col].fillna("")

            return df

        except Exception as e:
            raise RuntimeError(f"Failed to load logs: {str(e)}")
