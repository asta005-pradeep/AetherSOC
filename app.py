import os
import json
from flask import Flask, render_template, jsonify, send_from_directory, request
from main import run_pipeline
from simulate_attack import generate_noise, generate_attacks

app = Flask(__name__)

# Basic paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
ALERTS_FILE = os.path.join(DATA_DIR, 'final_enriched_alerts.json')
VALID_STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED"}

def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []

    with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
        alerts = json.load(f)

    changed = False
    for idx, alert in enumerate(alerts):
        if not alert.get("id"):
            alert["id"] = f"ALERT_{idx+1:03d}"
            changed = True
        if alert.get("status") not in VALID_STATUSES:
            alert["status"] = "OPEN"
            changed = True
        if "assigned_to" not in alert:
            alert["assigned_to"] = None
            changed = True
        if not isinstance(alert.get("notes"), list):
            alert["notes"] = []
            changed = True

    if changed:
        save_alerts(alerts)

    return alerts

def save_alerts(alerts):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=4)

def find_alert(alerts, alert_id):
    for alert in alerts:
        if alert.get('id') == alert_id:
            return alert
    return None

def assign_alert_record(alert_id, analyst):
    if not alert_id or not analyst:
        return {"error": "id and analyst are required"}, 400

    alerts = load_alerts()
    alert = find_alert(alerts, alert_id)
    if not alert:
        return {"error": "Alert not found"}, 404

    alert['assigned_to'] = analyst
    save_alerts(alerts)
    return {"status": "success", "alert": alert}, 200

def update_alert_status_record(alert_id, status):
    if not alert_id or not status:
        return {"error": "id and status are required"}, 400
    if status not in VALID_STATUSES:
        return {"error": "Invalid status"}, 400

    alerts = load_alerts()
    alert = find_alert(alerts, alert_id)
    if not alert:
        return {"error": "Alert not found"}, 404

    alert['status'] = status
    save_alerts(alerts)
    return {"status": "success", "alert": alert}, 200

def add_alert_note_record(alert_id, note):
    if not alert_id or not note:
        return {"error": "id and note are required"}, 400

    alerts = load_alerts()
    alert = find_alert(alerts, alert_id)
    if not alert:
        return {"error": "Alert not found"}, 404

    alert.setdefault('notes', []).append(note)
    save_alerts(alerts)
    return {"status": "success", "alert": alert}, 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    import pandas as pd
    try:
        noise = generate_noise(500)
        attacks = generate_attacks()
        all_events = noise + attacks
        all_events.sort(key=lambda x: x['Timestamp'])
        
        os.makedirs(DATA_DIR, exist_ok=True)
        output_path = os.path.join(DATA_DIR, "sysmon_logs.csv")
        df = pd.DataFrame(all_events)
        df.to_csv(output_path, index=False)
        
        return jsonify({"status": "success", "message": f"Generated {len(all_events)} events."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/run', methods=['POST'])
def api_run_pipeline():
    try:
        result = run_pipeline()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def api_get_alerts():
    try:
        return jsonify(load_alerts())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/assign', methods=['POST'])
def assign_alert():
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get('id') or payload.get('alert_id')
    analyst = (payload.get('analyst') or payload.get('assigned_to') or '').strip()
    response, status_code = assign_alert_record(alert_id, analyst)
    return jsonify(response), status_code

@app.route('/status', methods=['POST'])
def update_alert_status():
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get('id') or payload.get('alert_id')
    status = (payload.get('status') or '').strip().upper()
    response, status_code = update_alert_status_record(alert_id, status)
    return jsonify(response), status_code

@app.route('/note', methods=['POST'])
def add_alert_note():
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get('id') or payload.get('alert_id')
    note = (payload.get('note') or '').strip()
    response, status_code = add_alert_note_record(alert_id, note)
    return jsonify(response), status_code

@app.route('/api/alerts/<alert_id>/assign', methods=['POST'])
def api_assign_alert(alert_id):
    payload = request.get_json(silent=True) or {}
    analyst = (payload.get('analyst') or payload.get('assigned_to') or '').strip()
    response, status_code = assign_alert_record(alert_id, analyst)
    return jsonify(response), status_code

@app.route('/api/alerts/<alert_id>/status', methods=['POST'])
def api_status_alert(alert_id):
    payload = request.get_json(silent=True) or {}
    status = (payload.get('status') or '').strip().upper()
    response, status_code = update_alert_status_record(alert_id, status)
    return jsonify(response), status_code

@app.route('/api/alerts/<alert_id>/note', methods=['POST'])
def api_note_alert(alert_id):
    payload = request.get_json(silent=True) or {}
    note = (payload.get('note') or '').strip()
    response, status_code = add_alert_note_record(alert_id, note)
    return jsonify(response), status_code

@app.route('/data/<path:filename>')
def serve_data(filename):
    return send_from_directory(DATA_DIR, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
