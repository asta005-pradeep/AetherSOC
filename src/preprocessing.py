import pandas as pd
import numpy as np
import re

class SysmonPreprocessor:
    def __init__(self, file_path):
        """
        Initialize with the path to the Sysmon CSV file.
        """
        self.file_path = file_path

    def load_and_preprocess(self):
        """
        Loads Sysmon logs from a CSV file, extracts features, handles missing values,
        and outputs a clean numerical feature dataset suitable for ML models.
        """
        # 1. Load logs from CSV
        try:
            df = pd.read_csv(self.file_path)
        except Exception as e:
            raise RuntimeError(f"Failed to load CSV file: {e}")

        # 2. Extract useful fields (Initialize missing columns if they don't exist)
        expected_cols = ['EventID', 'Timestamp', 'ProcessName', 'ParentProcessName', 'CommandLine']
        for col in expected_cols:
            if col not in df.columns:
                df[col] = np.nan

        # 3. Handle missing values for categorical and text fields
        df['EventID'] = df['EventID'].fillna(-1).astype(int)
        df['ProcessName'] = df['ProcessName'].fillna("unknown_process")
        df['ParentProcessName'] = df['ParentProcessName'].fillna("unknown_parent")
        df['CommandLine'] = df['CommandLine'].fillna("")
        
        # Forward fill and backward fill missing timestamps as a fallback
        df['Timestamp'] = df['Timestamp'].ffill().bfill()

        # 4. Convert timestamps to numerical features
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        
        df = df.dropna(subset=['Timestamp']).copy()
        
        df['hour_of_day'] = df['Timestamp'].dt.hour
        df['day_of_week'] = df['Timestamp'].dt.dayofweek

        # 5. Extract additional process info and compile final feature dataset
        features = pd.DataFrame(index=df.index)
        
        features['hour_of_day'] = df['hour_of_day']
        features['day_of_week'] = df['day_of_week']
        
        # Command line complexity
        features['cmd_length'] = df['CommandLine'].apply(len)
        features['special_char_count'] = df['CommandLine'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9\s.\-\\]', x)))
        
        # Categorical frequency encoding for process name (rarity of process) - heavily weighted
        process_freq = df['ProcessName'].value_counts(normalize=True).to_dict()
        features['process_frequency'] = df['ProcessName'].map(process_freq)
        
        # Parent-child relation frequency
        df['parent_child'] = df['ParentProcessName'] + "->" + df['ProcessName']
        pc_freq = df['parent_child'].value_counts(normalize=True).to_dict()
        features['parent_child_frequency'] = df['parent_child'].map(pc_freq)

        # Ensure dataset is completely clean (no NaNs)
        features = features.fillna(0)

        return features

if __name__ == "__main__":
    pass
