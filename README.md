# 🛡️ Enterprise CTI Dashboard (Cyber Threat Intelligence)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)
[![Flask](https://img.shields.io/badge/Flask-Backend-green.svg)](https://flask.palletsprojects.com/)

A completely automated, real-time **Cyber Threat Intelligence (CTI) Platform** that acts as a modern Security Operations Center (SOC). This system autonomously ingests live threat data from global OSINT feeds, scores malicious activity using custom Machine Learning logic, and plots real-time attacks on a dynamic interactive world map.

---

## 🔗 Live Deployments

The platform is fully containerized and currently deployed live on Render. You can access the live dashboard right now!

- **🟢 Live Frontend Dashboard:** [https://cti-dashboard-uwb0.onrender.com](https://cti-dashboard-uwb0.onrender.com)
  - *Login Credentials:* `admin` / `password123`
- **⚙️ Live Backend API:** [https://cti-dashboard1.onrender.com/api/status](https://cti-dashboard1.onrender.com/api/status)

---

## ✨ Core Capabilities & Features

- **🌐 Live Global Threat Map** — Built with `react-simple-maps` and `d3-geo`, this dark-themed interactive world map visually plots the exact geographic coordinates of incoming cyber threats as they are detected globally.
- **🚨 Automated Discord Alerting** — The backend automatically pushes high-priority alerts directly to a designated Discord webhook whenever a **CRITICAL** severity threat (such as Ransomware) is identified.
- **🧠 ML-Powered Risk Scoring** — A custom machine learning algorithm evaluates incoming threats (analyzing confidence scores and malware families) to intelligently assign severity levels: **CRITICAL**, **HIGH**, **MEDIUM**, or **LOW**.
- **📡 Autonomous Data Ingestion** — A continuous Python background thread automatically scrapes and pulls live Botnet C2 servers and malicious URLs from [Feodo Tracker](https://feodotracker.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/) every 30 seconds.
- **🧹 Data Retention Automation** — To ensure database performance and optimize cloud storage, the system continuously runs a background cleanup protocol that permanently deletes threat data older than 30 days.
- **📊 Interactive Analytics** — Features beautifully animated charts (powered by Recharts) that visualize threat distributions by type, source, top malware families, and temporal detection trends.
- **🔒 Secure Architecture** — The API is entirely locked down using JSON Web Tokens (JWT). The frontend gracefully handles token expiration with Axios interceptors to redirect unauthorized sessions.

---

## 🛠️ Skills Used & Tech Stack

This project was built utilizing a wide range of modern software engineering and cybersecurity skills:

### **Frontend Engineering**
- **React 18** — Component-based UI architecture and Hooks (`useState`, `useEffect`, `useCallback`)
- **TailwindCSS** — Rapid utility-first styling for a sleek, dark-themed glassmorphic UI
- **Recharts** — Declarative composition of React data visualization components
- **React Simple Maps (D3-Geo / TopoJSON)** — Complex SVG geographic mapping and coordinate plotting
- **Axios** — Asynchronous HTTP requests and request/response interception

### **Backend Engineering**
- **Python / Flask** — Lightweight, highly scalable RESTful API development
- **Flask-SQLAlchemy** — ORM for robust database querying and schema modeling
- **Flask-JWT-Extended** — Secure, token-based stateless authentication
- **Threading** — Asynchronous Python background workers for non-blocking data fetching
- **Gunicorn** — Production-ready Python WSGI HTTP Server

### **Cybersecurity & Data Science**
- **OSINT Integration** — Parsing and utilizing Open Source Intelligence feeds
- **Pandas & Scikit-Learn** — Data manipulation and machine learning algorithms for risk assessment
- **MITRE ATT&CK** — Integration of the global standard STIX dataset for malware and threat mitigation reference

---

## 📂 Project Architecture

```
CTI-Dashboard/
├── backend/
│   ├── app.py            # Main Flask REST API & Thread Managers
│   ├── osint.py          # OSINT Web Scrapers (Feodo, URLhaus) & Coordinate Generators
│   ├── ml_scorer.py      # ML Threat Analysis & Scoring Logic
│   ├── models.py         # SQLAlchemy Database Schemas
│   └── requirements.txt  # Python Dependencies
└── frontend/
    ├── src/
    │   ├── App.js         # Main Dashboard Layout & API Integration
    │   ├── ThreatMap.js   # D3 Geographic Map Component
    │   └── Login.js       # JWT Authentication Interface
    └── package.json       # Node.js Dependencies
```

---

## 🚀 Running Locally

If you want to run this enterprise platform on your own local machine, follow these steps:

### 1. Setup the Backend
Open a terminal and navigate to the `backend` directory:
```bash
cd backend
pip install -r requirements.txt
python app.py
```
*The backend will start at `http://localhost:5000` and automatically create the SQLite database.*

### 2. Setup the Frontend
Open a second terminal and navigate to the `frontend` directory:
```bash
cd frontend
npm install
npm start
```
*The dashboard will automatically open in your browser at `http://localhost:3000`.*

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete details. You are free to use, modify, and distribute this software as you see fit!
