import pandas as pd
from sklearn.ensemble import IsolationForest

class SysmonAnomalyDetector:
    def __init__(self, contamination=0.01, n_estimators=250, max_samples='auto'):
        """
        Initialize the Isolation Forest model for Sysmon Anomaly Detection.
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination=contamination,
            random_state=42 # Set for reproducibility
        )

    def train(self, normal_features_df):
        """
        Trains the Isolation Forest model.
        """
        if normal_features_df.empty:
            raise ValueError("Training data is empty.")
        
        print("[*] Training Isolation Forest model on baseline data...")
        self.model.fit(normal_features_df)
        print("[+] Training complete.")

    def predict_and_save(self, features_df, original_df, output_csv="anomaly_results.csv"):
        """
        Predicts anomalies on the target dataset, computes anomaly scores, 
        and saves the combined results to a CSV file.
        """
        if features_df.empty:
            raise ValueError("Feature dataset is empty.")

        # 1. Predict labels: 1 for inliers (normal), -1 for outliers (anomalies)
        labels = self.model.predict(features_df)
        
        # 2. Calculate anomaly scores: Lower scores (negative) indicate high anomaly potential.
        scores = self.model.decision_function(features_df)

        # 3. Combine results with original data
        results_df = original_df.copy()
        results_df['anomaly_label'] = labels
        results_df['anomaly_score'] = scores
        
        # Add a clear boolean column for ease of filtering (only keeping negative scores as per contamination)
        results_df['is_anomaly'] = results_df['anomaly_score'].apply(lambda x: True if x < 0 else False)

        # Remove duplicate alerts based on ProcessName and CommandLine to reduce noise
        before_dedup = results_df['is_anomaly'].sum()
        
        # Deduplicate the anomalies, but keep normal traffic intact
        anomalies_df = results_df[results_df['is_anomaly']].drop_duplicates(subset=['ProcessName', 'CommandLine'])
        normals_df = results_df[~results_df['is_anomaly']]
        
        # Recombine
        results_df = pd.concat([normals_df, anomalies_df]).sort_index()

        # --- Debug Outputs ---
        anomalies_count = anomalies_df.shape[0]
        print(f"\n[ML DEBUG] Score Distribution:")
        print(f"  - Min Score:  {scores.min():.4f} (Most anomalous)")
        print(f"  - Mean Score: {scores.mean():.4f}")
        print(f"  - Max Score:  {scores.max():.4f} (Most normal)")
        print(f"[ML DEBUG] Detected {before_dedup} anomalies initially. After deduplication: {anomalies_count} unique anomalies.")
        
        if anomalies_count > 0:
            print("\n[ML DEBUG] Top 5 Anomalies:")
            sample_anomalies = anomalies_df.sort_values(by='anomaly_score').head(5)
            for _, row in sample_anomalies.iterrows():
                print(f"  -> Score: {row['anomaly_score']:.4f} | Process: {row.get('ProcessName')} | Cmd: {row.get('CommandLine')[:80]}...")

        # 4. Save results to CSV
        results_df.to_csv(output_csv, index=False)
        print(f"\n[+] Anomaly detection complete. Results saved to {output_csv}")
        
        return results_df

if __name__ == "__main__":
    pass
