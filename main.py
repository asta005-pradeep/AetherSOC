import os
import pandas as pd

# Import the custom modules
from src.preprocessing import SysmonPreprocessor
from src.anomaly_detection import SysmonAnomalyDetector
from src.rule_engine import SigmaRuleEngine
from src.mitre_mapper import MitreMapper

DEFAULT_ALERT_STATUS = "OPEN"

def run_pipeline():
    print("="*50)
    print(" AetherSOC - Integrated Threat Hunting Pipeline ")
    print("="*50)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(base_dir, 'data', 'sysmon_logs.csv')
    output_alerts_file = os.path.join(base_dir, 'data', 'final_enriched_alerts.json')

    # Ensure the data directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    if not os.path.exists(log_file):
        print(f"[-] Error: {log_file} not found.")
        print("[*] Please ensure you have a valid Sysmon CSV log file at that location.")
        return

    # 1. Load Logs and Preprocess
    print("\n[+] Phase 1: Preprocessing Logs...")
    preprocessor = SysmonPreprocessor(log_file)
    features_df = preprocessor.load_and_preprocess()
    
    # We also need the original logs for the Rule Engine to evaluate text fields
    original_df = pd.read_csv(log_file)
    
    # Ensure missing columns are handled in original_df so rule engine doesn't crash
    expected_cols = ['EventID', 'Timestamp', 'ProcessName', 'CommandLine']
    for col in expected_cols:
        if col not in original_df.columns:
            original_df[col] = ""

    # 2. Machine Learning Anomaly Detection
    print("\n[+] Phase 2: Running ML Anomaly Detection...")
    # In a real environment, you'd train on a known clean dataset.
    # Here, we train on the input dataset (assuming anomalies are rare outliers).
    detector = SysmonAnomalyDetector(contamination=0.02)
    detector.train(features_df)
    
    # Predict and append results to the original logs
    results_df = detector.predict_and_save(features_df, original_df, os.path.join(base_dir, "data", "anomaly_results.csv"))
    
    # Extract ML anomalies to convert them to alerts
    ml_anomalies = results_df[results_df['is_anomaly'] == True].copy()
    
    # 1. REMOVE DUPLICATES & 3. FILTER NORMAL PROCESSES
    # Sort by anomaly score to keep the most severe instance when dropping duplicates
    ml_anomalies = ml_anomalies.sort_values(by='anomaly_score', ascending=True)
    ml_anomalies = ml_anomalies.drop_duplicates(subset=['ProcessName', 'CommandLine'])
    
    ml_alerts = []
    common_procs = ['chrome.exe', 'explorer.exe', 'svchost.exe', 'notepad.exe', 'msedge.exe']
    
    for _, row in ml_anomalies.iterrows():
        proc_name = str(row.get("ProcessName", "N/A"))
        score = float(row.get("anomaly_score", 0.0))
        
        # Filter normal processes unless the score is VERY strong (e.g., < -0.15)
        if proc_name.lower() in common_procs and score >= -0.15:
            continue
            
        ml_alerts.append({
            "rule_id": "ML_ANOMALY",
            "rule_name": "Isolation Forest Anomaly Detected",
            "severity": "High",
            "timestamp": str(row.get("Timestamp", "N/A")),
            "process_name": proc_name,
            "matched_field": "Multiple Features",
            "matched_value": str(row.get("CommandLine", "")),
            "anomaly_score": score
        })
        
    # 2. LIMIT ML ALERTS to TOP 5
    ml_alerts = sorted(ml_alerts, key=lambda x: x['anomaly_score'])[:5]
    print(f"    Detected {len(ml_alerts)} meaningful ML anomalies after filtering.")

    # 3. Apply Sigma Rules
    print("\n[+] Phase 3: Applying Sigma-like Rules...")
    rule_engine = SigmaRuleEngine()
    rule_alerts = rule_engine.process_logs(results_df)

    # 1. REMOVE ML DUPLICATES IF RULE EXISTS
    rule_caught_signatures = set()
    for r_alert in rule_alerts:
        sig = (r_alert.get('process_name'), r_alert.get('matched_value'))
        rule_caught_signatures.add(sig)

    filtered_ml_alerts = []
    for m_alert in ml_alerts:
        sig = (m_alert.get('process_name'), m_alert.get('matched_value'))
        if sig not in rule_caught_signatures:
            filtered_ml_alerts.append(m_alert)

    # Combine both sets of alerts (Rule alerts have priority)
    all_raw_alerts = rule_alerts + filtered_ml_alerts
    
    # 2. REMOVE INTERNAL DUPLICATES
    unique_alerts = []
    seen = set()
    for alert in all_raw_alerts:
        key = (alert.get('process_name'), alert.get('matched_value'))
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    # 4. Map to MITRE ATT&CK & Generate Final Alerts
    print("\n[+] Phase 4: Mapping to MITRE ATT&CK and Generating Final Alerts...")
    mitre_mapper = MitreMapper()
    final_enriched_alerts = mitre_mapper.process_alerts(unique_alerts)
    
    # 4. PRIORITIZE ALERTS (Critical -> High -> Medium -> Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    final_enriched_alerts.sort(key=lambda x: severity_order.get(x.get('event_details', {}).get('severity', 'Low'), 4))
    
    # NEW: Add SOC Analyst fields
    for idx, alert in enumerate(final_enriched_alerts):
        alert["id"] = f"ALERT_{idx+1:03d}"
        alert["status"] = DEFAULT_ALERT_STATUS
        alert["assigned_to"] = None
        alert["notes"] = []

    mitre_mapper.save_enriched_alerts(final_enriched_alerts, output_alerts_file)

    # 5. CLEAN OUTPUT FORMAT
    print("\n" + "="*50)
    print(f"[+] Pipeline Complete! {len(final_enriched_alerts)} clean alerts generated.")
    print("="*50)
    print("Final Alert Summary:")
    for alert in final_enriched_alerts:
        details = alert.get('event_details', {})
        print(f"[{details.get('severity', 'INFO')}] {details.get('rule_name')} | Proc: {details.get('process_name')}")
    
    return {
        "status": "success",
        "alerts_generated": len(final_enriched_alerts),
        "ml_anomalies": len(ml_alerts)
    }

if __name__ == "__main__":
    run_pipeline()
