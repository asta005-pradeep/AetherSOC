import json

class MitreMapper:
    def __init__(self):
        """
        Initializes the MITRE ATT&CK mapper with a predefined mapping dictionary.
        Maps specific rule IDs or heuristic keywords to MITRE Technique IDs.
        """
        self.technique_mapping = self._load_mappings()

    def _load_mappings(self):
        """
        Returns a dictionary mapping rule IDs (or keywords) to MITRE ATT&CK details.
        """
        return {
            "SIGMA_001": {
                "technique_id": "T1059.001",
                "tactic": "Execution",
                "description": "PowerShell. Adversaries may abuse PowerShell commands and scripts for execution."
            },
            "SIGMA_002": {
                "technique_id": "T1059.001",
                "tactic": "Execution",
                "description": "PowerShell Execution Policy Bypass. Used to run unsigned/unauthorized scripts."
            },
            "SIGMA_003": {
                "technique_id": "T1003.001",
                "tactic": "Credential Access",
                "description": "OS Credential Dumping: LSASS Memory. Extracting credentials from the Local Security Authority Subsystem Service."
            },
            "SIGMA_004": {
                "technique_id": "T1490",
                "tactic": "Impact",
                "description": "Inhibit System Recovery. Deleting volume shadow copies to prevent restoration."
            },
            "SIGMA_005": {
                "technique_id": "T1027",
                "tactic": "Defense Evasion",
                "description": "Obfuscated Files or Information. Adversaries may obfuscate command lines to evade detection."
            },
            # Keyword fallbacks for ML anomalies that don't have a specific Rule ID
            "KEYWORD_NETWORK": {
                "technique_id": "T1046",
                "tactic": "Discovery",
                "description": "Network Service Scanning. Adversaries may scan networks to gather information over IP/Ports."
            },
            "KEYWORD_CMD": {
                "technique_id": "T1059.003",
                "tactic": "Execution",
                "description": "Windows Command Shell. Adversaries may abuse cmd.exe."
            }
        }

    def map_event(self, alert_event):
        """
        Takes an alert event (dictionary) and enriches it with MITRE ATT&CK context.
        
        :param alert_event: Dictionary representing an alert (e.g., from Sigma Engine)
        :return: A structured dictionary with MITRE context added.
        """
        rule_id = alert_event.get("rule_id")
        # In case there's no rule ID (like a raw ML anomaly), fallback to command line analysis
        command_line = str(alert_event.get("matched_value", alert_event.get("CommandLine", ""))).lower()

        # Try mapping by exact Rule ID first
        if rule_id and rule_id in self.technique_mapping:
            mitre_info = self.technique_mapping[rule_id]
        
        # Fallback to keyword matching (e.g., for ML anomalies or unknown rules)
        elif "nmap" in command_line or "scan" in command_line or "ping" in command_line:
            mitre_info = self.technique_mapping["KEYWORD_NETWORK"]
        elif "cmd.exe" in command_line:
            mitre_info = self.technique_mapping["KEYWORD_CMD"]
        else:
            # Generic unknown mapping
            mitre_info = {
                "technique_id": "Unknown",
                "tactic": "Unknown / Suspicious Behavior",
                "description": "Event matched detection criteria but lacks a specific MITRE mapping."
            }

        # Construct the enriched structured alert
        structured_alert = {
            "event_details": alert_event,
            "mitre_technique_id": mitre_info["technique_id"],
            "mitre_tactic": mitre_info["tactic"],
            "mitre_description": mitre_info["description"]
        }

        return structured_alert

    def process_alerts(self, alerts_list):
        """
        Iterates over a list of alerts and enriches all of them.
        """
        enriched_alerts = []
        for alert in alerts_list:
            enriched_alerts.append(self.map_event(alert))
            
        return enriched_alerts

    def save_enriched_alerts(self, enriched_alerts, output_file="enriched_alerts.json"):
        """Saves the final structured alerts to JSON."""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(enriched_alerts, f, indent=4)
        print(f"[+] Successfully mapped and saved {len(enriched_alerts)} alerts to {output_file}")

if __name__ == "__main__":
    # Example usage:
    # mapper = MitreMapper()
    # enriched = mapper.process_alerts(raw_sigma_alerts)
    # mapper.save_enriched_alerts(enriched, "data/enriched_alerts.json")
    pass
