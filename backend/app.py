# app.py — Flask backend API for CTI Dashboard
from flask import Flask, jsonify
from flask_cors import CORS
from osint import get_all_threats, get_sample_threats
from ml_scorer import analyse_threats, get_summary
import threading
import time
import json
import random
import os

app = Flask(__name__)
CORS(app)

# Load MITRE data once at startup
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

# ---- File-based threat cache ----
# Using a file instead of an in-memory variable so that ALL gunicorn worker
# processes see the same data (in-memory globals are NOT shared between
# separate worker processes).
CACHE_FILE = "threats_cache.json"
CACHE_LOCK = threading.Lock()

def write_cache(threats, last_updated):
    with CACHE_LOCK:
        with open(CACHE_FILE, "w") as f:
            json.dump({"threats": threats, "last_updated": last_updated}, f)

def read_cache():
    if not os.path.exists(CACHE_FILE):
        return [], None
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
        return data.get("threats", []), data.get("last_updated")
    except Exception:
        return [], None

def refresh_threats():
    """Background thread to refresh threats every 30 seconds and write to disk."""
    while True:
        print("[*] Fetching latest threats...")
        threats = get_all_threats()
        extra = random.sample(get_sample_threats(), random.randint(1, 4))
        threats = threats + extra
        scored = analyse_threats(threats)
        last_updated = time.strftime("%Y-%m-%d %H:%M:%S")
        write_cache(scored, last_updated)
        print(f"[*] Fetched {len(scored)} threats")
        time.sleep(30)

@app.route("/api/threats")
def get_threats():
    threats, last_updated = read_cache()
    return jsonify({
        "status": "ok",
        "last_updated": last_updated,
        "data": threats[:50]
    })

@app.route("/api/summary")
def get_summary_route():
    threats, _ = read_cache()
    summary = get_summary(threats)
    return jsonify(summary)

@app.route("/api/threats/critical")
def get_critical():
    threats, _ = read_cache()
    critical = [t for t in threats if t["severity"] == "CRITICAL"]
    return jsonify({"status": "ok", "data": critical})

@app.route("/api/threats/by-type")
def get_by_type():
    threats, _ = read_cache()
    types = {}
    for t in threats:
        ioc_type = t.get("type", "unknown")
        types[ioc_type] = types.get(ioc_type, 0) + 1
    return jsonify(types)

@app.route("/api/threats/by-source")
def get_by_source():
    threats, _ = read_cache()
    sources = {}
    for t in threats:
        source = t.get("source", "unknown")
        sources[source] = sources.get(source, 0) + 1
    return jsonify(sources)

@app.route("/api/status")
def status():
    threats, last_updated = read_cache()
    return jsonify({
        "status": "running",
        "threats_loaded": len(threats),
        "last_updated": last_updated
    })

# Start the background refresh thread. Even if gunicorn runs more than one
# worker process, each worker writes to the SAME cache file, so every
# request (no matter which worker handles it) reads up-to-date data.
t = threading.Thread(target=refresh_threats, daemon=True)
t.start()
print("[*] Background refresh thread started")

if __name__ == "__main__":
    print("[*] CTI Dashboard API running at http://localhost:5000")
    app.run(debug=True, port=5000)
