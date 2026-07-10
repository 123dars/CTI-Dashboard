from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Threat(db.Model):
    __tablename__ = 'threats'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), unique=True, nullable=False) # e.g. IP or URL
    type = db.Column(db.String(50), nullable=False) # ipv4, url
    source = db.Column(db.String(50), nullable=False) # feodo, urlhaus
    severity = db.Column(db.String(20), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    risk_score = db.Column(db.Float, nullable=False)
    lat = db.Column(db.Float, nullable=True)
    lon = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
