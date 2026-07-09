# app.py — Flask backend API for CTI Dashboard
from flask import Flask, jsonify, request
from flask_cors import CORS
from osint import get_all_threats, get_sample_threats
from ml_scorer import analyse_threats, get_summary
from models import db, User, Threat
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
import traceback
from collections import deque
from datetime import datetime

thread_logs = deque(maxlen=50)

def log_msg(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    thread_logs.appendleft(f"[{ts}] {msg}")
    print(msg)

from flask import Flask, jsonify, request
from flask_cors import CORS
from osint import get_all_threats, get_sample_threats
from ml_scorer import analyse_threats, get_summary
from models import db, User, Threat
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app)

# --- Configuration ---
db_url = os.environ.get('DATABASE_URL', 'sqlite:///cti.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')

db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Load MITRE data once at startup
with open("cti_data.json") as f:
    cti_data = json.load(f)

# --- Database Initialization ---
def init_db():
    with app.app_context():
        db.create_all()
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            hashed_pw = bcrypt.generate_password_hash('password123').decode('utf-8')
            admin = User(username='admin', password_hash=hashed_pw)
            db.session.add(admin)
            db.session.commit()
            print("[*] Admin user created.")

# --- Authentication Routes ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid credentials"}), 401

# --- MITRE Routes ---
@app.route("/api/malware")
@jwt_required()
def get_malware():
    return jsonify(cti_data["malware"])

@app.route("/api/techniques")
@jwt_required()
def get_techniques():
    return jsonify(cti_data["techniques"])

@app.route("/api/groups")
@jwt_required()
def get_groups():
    return jsonify(cti_data["groups"])

@app.route("/api/mitigations")
@jwt_required()
def get_mitigations():
    return jsonify(cti_data["mitigations"])

@app.route("/api/all")
@jwt_required()
def get_all():
    return jsonify(cti_data)

# --- Background Refresh Thread ---
def refresh_threats():
    """Background thread to refresh threats every 30 seconds and write to DB."""
    log_msg("[*] Thread actually started execution inside worker.")
    while True:
        try:
            log_msg("[*] Fetching latest threats...")
            threats = get_all_threats()
            extra = random.sample(get_sample_threats(), random.randint(1, 4))
            threats = threats + extra
            scored = analyse_threats(threats)
            log_msg(f"[*] Analyse threats returned {len(scored)} items")
            
            with app.app_context():
                inserted = 0
                seen_iocs_in_batch = set()
                
                for t in scored:
                    ioc_truncated = str(t['ioc'])[:255]
                    
                    if ioc_truncated in seen_iocs_in_batch:
                        continue
                    seen_iocs_in_batch.add(ioc_truncated)
                    
                    if not Threat.query.filter_by(indicator=ioc_truncated).first():
                        new_threat = Threat(
                            indicator=ioc_truncated,
                            type=str(t.get('type', 'unknown'))[:50],
                            source=str(t.get('source', 'unknown'))[:50],
                            severity=str(t.get('severity', 'LOW'))[:20],
                            risk_score=float(t.get('risk_score', 0))
                        )
                        db.session.add(new_threat)
                        inserted += 1
                try:
                    db.session.commit()
                    log_msg(f"[*] Fetched and scored threats. Inserted {inserted} new IOCs into DB.")
                except Exception as db_err:
                    db.session.rollback()
                    log_msg(f"[!] DB Error during commit, rolled back: {db_err}")
        except Exception as e:
            log_msg(f"[!] Error in refresh thread: {e}")
            log_msg(traceback.format_exc())
        time.sleep(30)

# --- API Routes ---
@app.route("/api/threats")
@jwt_required()
def get_threats():
    threats = Threat.query.order_by(Threat.timestamp.desc()).limit(100).all()
    threats_list = [{
        "indicator": t.indicator,
        "type": t.type,
        "source": t.source,
        "severity": t.severity,
        "risk_score": t.risk_score,
        "timestamp": t.timestamp.isoformat()
    } for t in threats]
    
    return jsonify({
        "status": "ok",
        "data": threats_list
    })

@app.route("/api/summary")
@jwt_required()
def get_summary_route():
    threats = Threat.query.all()
    # Mocking the dictionary structure for ml_scorer compatibility
    threats_dicts = [{"severity": t.severity, "risk_score": t.risk_score} for t in threats]
    summary = get_summary(threats_dicts)
    return jsonify(summary)

@app.route("/api/threats/critical")
@jwt_required()
def get_critical():
    threats = Threat.query.filter_by(severity="CRITICAL").order_by(Threat.timestamp.desc()).limit(50).all()
    threats_list = [{
        "indicator": t.indicator,
        "type": t.type,
        "source": t.source,
        "severity": t.severity,
        "risk_score": t.risk_score,
        "timestamp": t.timestamp.isoformat()
    } for t in threats]
    return jsonify({"status": "ok", "data": threats_list})

@app.route("/api/threats/by-type")
@jwt_required()
def get_by_type():
    from sqlalchemy import func
    types_query = db.session.query(Threat.type, func.count(Threat.id)).group_by(Threat.type).all()
    types = {t[0]: t[1] for t in types_query}
    return jsonify(types)

@app.route("/api/threats/by-source")
@jwt_required()
def get_by_source():
    from sqlalchemy import func
    sources_query = db.session.query(Threat.source, func.count(Threat.id)).group_by(Threat.source).all()
    sources = {s[0]: s[1] for s in sources_query}
    return jsonify(sources)

@app.route("/api/status")
def status():
    return jsonify({
        "status": "running"
    })

# Run init_db before requests
init_db()

# Start background thread safely inside a worker process (fixes Gunicorn fork issues)
thread_started = False

@app.before_request
def start_background_thread():
    global thread_started
    if not thread_started:
        thread_started = True
        log_msg("[*] Attempting to start background thread in before_request")
        t = threading.Thread(target=refresh_threats, daemon=True)
        t.start()

@app.route("/api/logs")
def get_logs():
    return jsonify(list(thread_logs))

if __name__ == "__main__":
    print("[*] CTI Dashboard API running at http://localhost:5000")
    app.run(debug=True, port=5000, host="0.0.0.0")
