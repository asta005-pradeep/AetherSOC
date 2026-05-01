# AetherHunt – AI-Based Threat Hunting System

AetherHunt is a production-ready threat hunting system designed to detect malicious activities in Sysmon logs. It uses a hybrid approach combining Machine Learning (Isolation Forest) for anomaly detection and Rule-based logic (Sigma-like) for known threat detection. Detections are mapped to the MITRE ATT&CK framework.

## Project Structure
- `data/`: Contains sample Sysmon logs and generated alerts.
- `rules/`: Contains Sigma-like detection rules mapped to MITRE ATT&CK.
- `src/`: Core logic modules (ingestion, preprocessing, ML, rule engine, alerting, visualization).
- `main.py`: Orchestrates the entire pipeline.
- `simulate_attack.py`: Generates simulated Sysmon data including normal noise and specific attacks.

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate Simulated Data**
   Create the sample dataset of Sysmon logs with both benign and malicious activities:
   ```bash
   python simulate_attack.py
   ```
   This will generate `data/sample_sysmon_logs.json`.

3. **Run the Pipeline**
   Run the main threat hunting pipeline:
   ```bash
   python main.py
   ```
   This will:
   - Ingest logs from `data/sample_sysmon_logs.json`.
   - Process them through the Rule Engine (Sigma rules).
   - Process them through the ML Anomaly Detection model.
   - Output alerts to `data/alerts_output.json`.
   - Display an anomaly scatter plot.

## Architecture Modules
- **Ingestion**: Normalizes varied Sysmon logs into a consistent dataframe.
- **Preprocessing**: Converts log fields (e.g., CommandLine length, ProcessName) into numerical features for ML.
- **Anomaly Detection**: Scikit-learn's `IsolationForest` identifies outliers based on feature deviations.
- **Rule Engine**: Matches specific patterns like `powershell -enc` or `vssadmin delete shadows`.
- **Alert Generator**: Consolidates ML and Rule findings, attaching MITRE ATT&CK IDs (e.g., T1059.001).
- **Visualization**: Generates a Matplotlib graph showing anomaly scores, highlighting the attacks.
