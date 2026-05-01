import json
import os

class AlertGenerator:
    def __init__(self, output_file):
        self.output_file = output_file
        self.alerts = []

    def generate_alerts(self, df, ml_predictions, ml_scores, rule_engine):
        """
        Combines ML anomalies and Rule matches into a unified alert list.
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

        for index, row in df.iterrows():
            is_anomaly = ml_predictions[index] == -1
            score = ml_scores[index]
            
            # Evaluate Rules
            matched_rules = rule_engine.evaluate(row)
            
            # If it's an anomaly or matches a rule, generate an alert
            if is_anomaly or matched_rules:
                alert = {
                    "timestamp": str(row.get('Timestamp', '')),
                    "process_name": row.get('ProcessName', ''),
                    "parent_process_name": row.get('ParentProcessName', ''),
                    "command_line": row.get('CommandLine', ''),
                    "ml_anomaly": bool(is_anomaly),
                    "ml_score": float(score),
                    "rules_triggered": matched_rules,
                    "mitre_tactics": list(set([r['mitre_tactic'] for r in matched_rules])),
                    "mitre_techniques": list(set([r['mitre_technique'] for r in matched_rules]))
                }
                
                # Assign generic MITRE if only ML caught it
                if is_anomaly and not matched_rules:
                    alert["mitre_tactics"].append("Unknown / Suspicious Behavior")
                
                self.alerts.append(alert)

    def save_alerts(self):
        """
        Saves all generated alerts to the output JSON file.
        """
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(self.alerts, f, indent=4)
        print(f"[+] {len(self.alerts)} alerts generated and saved to {self.output_file}")
