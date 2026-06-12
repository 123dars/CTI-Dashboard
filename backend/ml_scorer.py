# ml_scorer.py — ML-based risk scoring for threat indicators

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import json

def calculate_risk_score(threat):
    """Calculate risk score for a single threat indicator"""
    score = 0
    
    # Base score from confidence level
    confidence = threat.get("confidence", 50)
    score += confidence * 0.3
    
    # Score based on threat type
    threat_type = str(threat.get("threat", "")).lower()
    if "botnet" in threat_type:
        score += 30
    elif "ransomware" in threat_type:
        score += 35
    elif "malware" in threat_type:
        score += 25
    elif "phishing" in threat_type:
        score += 20
    elif "exploit" in threat_type:
        score += 28
    else:
        score += 10

    # Score based on IOC type
    ioc_type = str(threat.get("type", "")).lower()
    if ioc_type in ["ip:port", "ip"]:
        score += 20
    elif ioc_type == "url":
        score += 15
    elif ioc_type == "domain":
        score += 18
    elif ioc_type == "md5_hash":
        score += 25
    elif ioc_type == "sha256_hash":
        score += 25
    else:
        score += 10

    # Cap score at 100
    score = min(round(score, 2), 100)
    return score

def classify_severity(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    else:
        return "LOW"

def analyse_threats(threats):
    """Analyse and score all threats"""
    results = []
    for threat in threats:
        risk_score = calculate_risk_score(threat)
        severity = classify_severity(risk_score)
        threat["risk_score"] = risk_score
        threat["severity"] = severity
        results.append(threat)
    
    # Sort by risk score descending
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results

def get_summary(threats):
    """Get summary statistics"""
    if not threats:
        return {}
    
    severities = [t["severity"] for t in threats]
    return {
        "total": len(threats),
        "critical": severities.count("CRITICAL"),
        "high": severities.count("HIGH"),
        "medium": severities.count("MEDIUM"),
        "low": severities.count("LOW"),
        "avg_score": round(sum(t["risk_score"] for t in threats) / len(threats), 2)
    }
