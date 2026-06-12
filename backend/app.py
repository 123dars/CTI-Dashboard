# app.py — Flask backend API for CTI Dashboard

from flask import Flask, jsonify
from flask_cors import CORS
from osint import get_all_threats
from ml_scorer import analyse_threats, get_summary
import threading
import time
import json
app = Flask(__name__)
CORS(app)

# Load data once at startup
with open("cti_data.json") as f:
    cti_data = json.load(f)

@app.route("/api/malware")
def get_malware():
    return jsonify(cti_data["malware"])

@app.route("/api/techniques")
def get_techniques():
    return jsonify(cti_data["techniques"])

@app.route("/api/groups")
def get_groups():
    return jsonify(cti_data["groups"])

@app.route("/api/mitigations")
def get_mitigations():
    return jsonify(cti_data["mitigations"])

@app.route("/api/all")
def get_all():
    return jsonify(cti_data)

# Cache threats to avoid hitting APIs too frequently
cached_threats = []
last_updated = None

def refresh_threats():
    """Background thread to refresh threats every 30 seconds"""
    global cached_threats, last_updated
    while True:
        print("[*] Fetching latest threats...")
        threats = get_all_threats()
        # Add new random threats each cycle to simulate live feed
        from osint import get_sample_threats
        import random
        extra = random.sample(get_sample_threats(), random.randint(1, 4))
        threats = threats + extra
        cached_threats = analyse_threats(threats)
        last_updated = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[*] Fetched {len(cached_threats)} threats")
        time.sleep(30)
@app.route("/api/threats")
def get_threats():
    return jsonify({
        "status": "ok",
        "last_updated": last_updated,
        "data": cached_threats[:50]
    })

@app.route("/api/summary")
def get_summary_route():
    summary = get_summary(cached_threats)
    return jsonify(summary)

@app.route("/api/threats/critical")
def get_critical():
    critical = [t for t in cached_threats if t["severity"] == "CRITICAL"]
    return jsonify({"status": "ok", "data": critical})

@app.route("/api/threats/by-type")
def get_by_type():
    types = {}
    for t in cached_threats:
        ioc_type = t.get("type", "unknown")
        types[ioc_type] = types.get(ioc_type, 0) + 1
    return jsonify(types)

@app.route("/api/threats/by-source")
def get_by_source():
    sources = {}
    for t in cached_threats:
        source = t.get("source", "unknown")
        sources[source] = sources.get(source, 0) + 1
    return jsonify(sources)

@app.route("/api/status")
def status():
    return jsonify({
        "status": "running",
        "threats_loaded": len(cached_threats),
        "last_updated": last_updated
    })

if __name__ == "__main__":
    # Start background thread
    t = threading.Thread(target=refresh_threats, daemon=True)
    t.start()
    print("[*] CTI Dashboard API running at http://localhost:5000")
    app.run(debug=True, port=5000)
