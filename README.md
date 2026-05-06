# 🛡️ AetherSOC – AI-Based Threat Hunting System

![AetherSOC Banner](https://img.shields.io/badge/Aether-SOC-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat)
![Flask](https://img.shields.io/badge/Flask-Web-green?style=flat)

AetherSOC is a production-ready, interactive threat hunting dashboard designed to detect malicious activities in Sysmon logs. It uses a powerful hybrid approach, combining **Machine Learning (Isolation Forest)** for anomaly detection and **Rule-based logic (Sigma-like)** for known threat detection. All detections are automatically mapped to the **MITRE ATT&CK®** framework to streamline incident response.

## ✨ Features
- **Interactive SOC Dashboard**: A sleek, dark-themed web interface to manage, investigate, and assign security alerts.
- **Machine Learning Detection**: Identifies zero-day anomalies using Scikit-learn's `IsolationForest`.
- **Rule-Based Detection**: Fast pattern matching against known adversarial techniques (e.g., encoded PowerShell, volume shadow copy deletion).
- **MITRE ATT&CK Mapping**: Alerts come pre-tagged with relevant MITRE tactics and techniques.
- **Data Simulation Engine**: Built-in tool to generate realistic Sysmon background noise alongside simulated cyber attacks for testing.

## 📁 Project Structure
- `app.py`: Main Flask application that powers the web dashboard and REST API.
- `main.py`: Orchestrates the ML and Rule-based threat detection pipeline.
- `simulate_attack.py`: Generates simulated Sysmon data (benign noise + specific attacks).
- `src/`: Core logic modules (ingestion, preprocessing, ML, rule engine, alerting, visualization).
- `rules/`: Contains Sigma-like JSON detection rules.
- `data/`: Contains sample datasets and generated alert output files.
- `templates/` & `static/`: Frontend HTML, CSS, and JavaScript for the interactive dashboard.

## 🚀 Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/AetherSOC.git
   cd AetherSOC
   ```

2. **Install Dependencies**
   Ensure you have Python 3.x installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the AetherSOC Dashboard**
   Start the Flask web server:
   ```bash
   python app.py
   ```
   *The dashboard will be available locally at: `http://127.0.0.1:5000`*

## 🛠️ Usage Pipeline
From the web dashboard, you can trigger data generation and threat analysis interactively. You can also run the core scripts manually via the terminal:

1. **Generate Data (`python simulate_attack.py`)**: Creates data with a mix of normal traffic and simulated attacks.
2. **Run Pipeline (`python main.py`)**: Ingests logs, runs them through the Rule Engine and ML models, and outputs `data/final_enriched_alerts.json`.
3. **Investigate**: Open the dashboard to assign alerts to analysts, update their status (`OPEN`, `IN_PROGRESS`, `RESOLVED`), and add investigation notes.

## 🧠 Architecture Modules
- **Ingestion**: Normalizes varied Sysmon logs into a consistent dataframe.
- **Preprocessing**: Converts log fields (e.g., CommandLine length, ProcessName) into numerical features for ML.
- **Anomaly Detection**: Scikit-learn's `IsolationForest` identifies outliers based on feature deviations.
- **Rule Engine**: Matches specific adversarial patterns.
- **Alert Generator**: Consolidates ML and Rule findings, attaching MITRE ATT&CK IDs (e.g., T1059.001).
- **Visualization**: Generates a Matplotlib graph showing anomaly scores.
