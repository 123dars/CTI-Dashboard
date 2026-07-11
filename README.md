# 🛡 CTI Dashboard — Cyber Threat Intelligence Dashboard

A real-time Cyber Threat Intelligence (CTI) dashboard that aggregates live threat data from open-source intelligence (OSINT) feeds, scores risk using a custom ML-based scorer, and visualizes indicators of compromise (IOCs), threat types, malware families, and detection trends.

## 🔗 Live Demo

- **Frontend Dashboard:** https://cti-dashboard-uwb0.onrender.com
- **Backend API:** https://cti-dashboard1.onrender.com

## ✨ Features

- **Live threat feed** — pulls real botnet C2 indicators from [Feodo Tracker](https://feodotracker.abuse.ch/) and malicious URLs from [URLhaus](https://urlhaus.abuse.ch/), auto-refreshing every 30 seconds
- **Risk scoring** — custom ML-based scoring assigns severity levels (CRITICAL / HIGH / MEDIUM / LOW) to each indicator
- **Interactive visualizations** — threats by type, threats by source, top malware families, and detection trend over time (via Recharts)
- **Global Threat Map** — dark-themed world map built with `react-simple-maps` that visually plots the live geographic coordinates of incoming threats
- **Automated Discord Alerting** — backend automatically pushes critical-severity threat alerts directly to a Discord webhook
- **Data Retention Policy** — continuous background thread automatically purges threats older than 30 days to optimize SQLite database storage
- **Searchable, filterable, paginated table** of live indicators of compromise (IOCs)
- **CSV export** of current threat data
- **MITRE ATT&CK integration** — static reference data for malware, techniques, threat groups, and mitigations sourced from the [MITRE ATT&CK STIX dataset](https://github.com/mitre/cti)

## 🏗 Tech Stack

**Frontend**
- React
- Recharts (data visualization)
- React Simple Maps & D3-Geo (geographic threat visualization)
- Axios (API calls)

**Backend**
- Flask (Python)
- Flask-CORS
- Background threading for periodic threat refresh & data retention
- Automated Discord Webhook alerting
- scikit-learn / pandas / numpy (risk scoring)
- Gunicorn (production WSGI server)

**Data Sources**
- [Feodo Tracker](https://feodotracker.abuse.ch/) — live botnet C2 IPs
- [URLhaus](https://urlhaus.abuse.ch/) — live malicious URLs
- [MITRE ATT&CK](https://attack.mitre.org/) — STIX 2.1 threat intelligence dataset (malware, techniques, threat groups, mitigations)

## 📂 Project Structure

```
CTI-Dashboard/
├── backend/
│   ├── app.py            # Flask API server
│   ├── osint.py          # Live threat feed fetchers (Feodo, URLhaus)
│   ├── ml_scorer.py       # Risk scoring & summary logic
│   ├── extract_data.py   # Extracts MITRE ATT&CK data into cti_data.json
│   ├── cti_data.json     # Processed MITRE ATT&CK reference data
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── App.js         # Main dashboard component
    │   └── App.css
    └── package.json
```

## 🚀 Running Locally (Enterprise Architecture)

The platform is fully containerized with a microservices architecture.

### Prerequisites
- Docker & Docker Compose
- Ports `80` (Frontend) and `5000` (Backend) must be free.

### Quick Start
To spin up the PostgreSQL database, Flask API, and React Frontend:

```bash
docker-compose up --build
```

### Accessing the Dashboard
- Navigate to `http://localhost`
- Default Admin Credentials: `admin` / `password123`

## 📡 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/threats` | Latest live threat indicators (auto-refreshed every 30s) |
| `GET /api/summary` | Summary stats (total, severity breakdown, avg risk score) |
| `GET /api/threats/critical` | Critical-severity threats only |
| `GET /api/threats/by-type` | Threat counts grouped by IOC type |
| `GET /api/threats/by-source` | Threat counts grouped by source |
| `GET /api/status` | Backend health/status check |
| `GET /api/malware` | MITRE ATT&CK malware reference data |
| `GET /api/techniques` | MITRE ATT&CK attack techniques |
| `GET /api/groups` | MITRE ATT&CK threat actor groups |
| `GET /api/mitigations` | MITRE ATT&CK mitigations |
| `GET /api/all` | All MITRE ATT&CK reference data combined |

## 🌐 Deployment

Both frontend and backend are deployed on [Render](https://render.com):
- **Frontend** — Static Site (`npm install && npm run build`, publish dir: `build`)
- **Backend** — Web Service (`pip install -r requirements.txt`, start: `gunicorn app:app`)

## 👤 Author

**Darshan B**

---
*Built with React, Flask, live OSINT threat feeds, and ML-based risk scoring.*
