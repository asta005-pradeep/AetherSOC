# AetherHunt Demo Scenarios

This document provides practical, realistic attack simulation examples you can use to demonstrate AetherHunt in an interview or live demo setting. These scenarios map directly to the detection capabilities built into the Rule Engine and the Machine Learning anomaly detector.

---

## Scenario 1: Fileless Malware (PowerShell Encoded Command)
Adversaries frequently use PowerShell with base64 encoded payloads to bypass execution policies and hide their intentions.

**The Attack Command:**
```cmd
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...
```

**What Sysmon Logs:**
Sysmon records a **Process Creation (Event ID 1)** event.
*   **ProcessName**: `powershell.exe`
*   **CommandLine**: The full string above containing `-EncodedCommand`.

**AetherHunt Expected Output:**
The Sigma Engine matches the encoded command regex (`SIGMA_001`).

```json
{
    "event_details": {
        "rule_id": "SIGMA_001",
        "rule_name": "Suspicious PowerShell Encoded Command",
        "severity": "High",
        "process_name": "powershell.exe",
        "matched_value": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz..."
    },
    "mitre_technique_id": "T1059.001",
    "mitre_tactic": "Execution",
    "mitre_description": "PowerShell. Adversaries may abuse PowerShell commands and scripts for execution."
}
```

---

## Scenario 2: Credential Dumping via LSASS
To move laterally, attackers often dump the memory of the Local Security Authority Subsystem Service (`lsass.exe`) to extract plaintext passwords or NTLM hashes.

**The Attack Command:**
```cmd
C:\Temp\procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
```

**What Sysmon Logs:**
Sysmon records a **Process Creation (Event ID 1)**.
*   **ProcessName**: `procdump.exe`
*   **CommandLine**: Contains both `procdump` and `lsass.exe`.

**AetherHunt Expected Output:**
The Sigma Engine triggers a critical alert for LSASS dumping (`SIGMA_003`).

```json
{
    "event_details": {
        "rule_id": "SIGMA_003",
        "rule_name": "Suspicious Process Dump (LSASS)",
        "severity": "Critical",
        "process_name": "procdump.exe",
        "matched_value": "C:\\Temp\\procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp"
    },
    "mitre_technique_id": "T1003.001",
    "mitre_tactic": "Credential Access",
    "mitre_description": "OS Credential Dumping: LSASS Memory. Extracting credentials from the Local Security Authority Subsystem Service."
}
```

---

## Scenario 3: Ransomware Behavior (Inhibit System Recovery)
Before encrypting files, ransomware typically deletes Volume Shadow Copies to prevent the victim from easily restoring their data.

**The Attack Command:**
```cmd
vssadmin.exe delete shadows /all /quiet
```

**What Sysmon Logs:**
Sysmon records a **Process Creation (Event ID 1)**.
*   **ProcessName**: `vssadmin.exe`
*   **CommandLine**: `vssadmin.exe delete shadows /all /quiet`

**AetherHunt Expected Output:**
The Sigma Engine immediately catches the `vssadmin delete shadows` syntax (`SIGMA_004`).

```json
{
    "event_details": {
        "rule_id": "SIGMA_004",
        "rule_name": "Volume Shadow Copy Deletion (Ransomware)",
        "severity": "Critical",
        "process_name": "vssadmin.exe",
        "matched_value": "vssadmin.exe delete shadows /all /quiet"
    },
    "mitre_technique_id": "T1490",
    "mitre_tactic": "Impact",
    "mitre_description": "Inhibit System Recovery. Deleting volume shadow copies to prevent restoration."
}
```

---

## Scenario 4: Unknown / Zero-Day Obfuscated Payload (Caught by ML)
Attackers sometimes use custom, never-before-seen droppers or heavily obfuscated command lines that bypass static rules.

**The Attack Command:**
```cmd
unknown_dropper_v2.exe !@#$%^&*() {malicious_payload_unpacking} --silent --bypass-hook
```

**What Sysmon Logs:**
Sysmon records a **Process Creation (Event ID 1)**.
*   **ProcessName**: `unknown_dropper_v2.exe` (A highly rare process in the dataset).
*   **CommandLine**: Contains an unusually high number of special characters and a strange length compared to the baseline.

**AetherHunt Expected Output:**
The static rules *miss* this because `unknown_dropper_v2.exe` isn't in a signature database. However, the **Isolation Forest** ML model flags it because the frequency of the process is near zero and the command line complexity deviates wildly from standard benign traffic (`explorer.exe`, `chrome.exe`).

```json
{
    "event_details": {
        "rule_id": "ML_ANOMALY",
        "rule_name": "Isolation Forest Anomaly Detected",
        "severity": "High",
        "process_name": "unknown_dropper_v2.exe",
        "matched_value": "unknown_dropper_v2.exe !@#$%^&*() {malicious_payload_unpacking} --silent --bypass-hook",
        "anomaly_score": -0.14532
    },
    "mitre_technique_id": "Unknown",
    "mitre_tactic": "Unknown / Suspicious Behavior",
    "mitre_description": "Event matched detection criteria but lacks a specific MITRE mapping."
}
```

---

### Demo Pro-Tip
If you are demonstrating this live in an interview:
1. Explain how **Scenarios 1-3** show the system's ability to act as a traditional SIEM using Sigma rules with low false positives.
2. Highlight **Scenario 4** as the "AI Advantage"—proving that the Machine Learning component catches unknown threats and anomalies that signature-based tools miss entirely.
