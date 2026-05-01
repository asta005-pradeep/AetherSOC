import re
import json

class SigmaRuleEngine:
    def __init__(self):
        """
        Initializes the Sigma-like rule engine with predefined detection rules.
        """
        self.rules = self._get_default_rules()
        self.alerts = []

    def _get_default_rules(self):
        """
        Defines the detection rules. In a full production system, 
        these would be loaded dynamically from external YAML/JSON files.
        """
        return [
            {
                "id": "SIGMA_001",
                "name": "Suspicious PowerShell Encoded Command",
                "severity": "High",
                "condition": "regex",
                "field": "CommandLine",
                # Matches PowerShell execution with Base64 encoded flags
                "pattern": r"(?i)powershell.*(?:-enc|-encodedcommand|-e\s)[a-z0-9+/=]+"
            },
            {
                "id": "SIGMA_002",
                "name": "PowerShell Execution Policy Bypass",
                "severity": "Medium",
                "condition": "contains",
                "field": "CommandLine",
                "pattern": "bypass"
            },
            {
                "id": "SIGMA_003",
                "name": "Suspicious Process Dump (LSASS)",
                "severity": "Critical",
                "condition": "contains_all",
                "field": "CommandLine",
                "pattern": ["procdump", "lsass"]
            },
            {
                "id": "SIGMA_004",
                "name": "Volume Shadow Copy Deletion (Ransomware)",
                "severity": "Critical",
                "condition": "contains_all",
                "field": "CommandLine",
                "pattern": ["vssadmin", "delete", "shadows"]
            },
            {
                "id": "SIGMA_005",
                "name": "Unusual Command-Line Pattern (Obfuscation)",
                "severity": "High",
                "condition": "regex",
                "field": "CommandLine",
                # Detects excessive use of special characters often used in batch obfuscation
                "pattern": r"([!^%\$]{2,}.*){3,}"
            }
        ]

    def add_rule(self, rule_dict):
        """Allows dynamically adding new rules to the engine."""
        self.rules.append(rule_dict)

    def evaluate_event(self, event):
        """
        Evaluates a single log event against all rules.
        
        :param event: A dictionary representing a single Sysmon log.
        :return: A list of alerts if any rules matched.
        """
        triggered_alerts = []

        for rule in self.rules:
            field_value = str(event.get(rule["field"], ""))
            if not field_value:
                continue

            is_match = False
            condition = rule["condition"]
            pattern = rule["pattern"]

            if condition == "contains":
                if pattern.lower() in field_value.lower():
                    is_match = True

            elif condition == "contains_all":
                if all(p.lower() in field_value.lower() for p in pattern):
                    is_match = True

            elif condition == "regex":
                if re.search(pattern, field_value):
                    is_match = True

            if is_match:
                alert = {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "timestamp": str(event.get("Timestamp", "N/A")),
                    "process_name": event.get("ProcessName", "N/A"),
                    "matched_field": rule["field"],
                    "matched_value": field_value
                }
                triggered_alerts.append(alert)

        return triggered_alerts

    def process_logs(self, logs_df):
        """
        Processes a pandas DataFrame of logs and collects all alerts.
        """
        print(f"[*] Processing {len(logs_df)} events against {len(self.rules)} rules...")
        
        # Convert DataFrame to list of dicts for processing
        events = logs_df.to_dict(orient="records")
        
        for event in events:
            matches = self.evaluate_event(event)
            if matches:
                self.alerts.extend(matches)
                
        print(f"[+] Rule evaluation complete. {len(self.alerts)} alerts generated.")
        return self.alerts

    def save_alerts(self, output_file="sigma_alerts.json"):
        """Saves triggered alerts to a JSON file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.alerts, f, indent=4)
        print(f"[+] Alerts saved to {output_file}")


if __name__ == "__main__":
    # Example usage:
    # engine = SigmaRuleEngine()
    # alerts = engine.process_logs(sysmon_dataframe)
    # engine.save_alerts("data/sigma_alerts.json")
    pass
