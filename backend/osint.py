import requests
from datetime import datetime

def get_feodo_threats():
    """Fetch real botnet C2 IPs from Feodo Tracker - no API key needed"""
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        response = requests.get(url, timeout=15)
        data = response.json()
        iocs = []
        for item in data[:30]:
            iocs.append({
                "ioc": f"{item.get('ip_address')}:{item.get('port')}",
                "type": "ip:port",
                "threat": "botnet_cc",
                "malware": item.get("malware"),
                "confidence": 95,
                "source": "Feodo Tracker",
                "timestamp": item.get("first_seen"),
                "country": item.get("country"),
                "status": item.get("status")
            })
        print(f"[*] Feodo returned {len(iocs)} real C2 indicators")
        return iocs
    except Exception as e:
        print(f"Feodo error: {e}")
        return []

def get_urlhaus_threats():
    try:
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        response = requests.get(url, timeout=15)
        data = response.json()
        threats = []
        if data.get("query_status") == "ok":
            for item in data.get("urls", [])[:20]:
                threats.append({
                    "ioc": item.get("url"),
                    "type": "url",
                    "threat": item.get("threat"),
                    "malware": item.get("tags"),
                    "confidence": 80,
                    "source": "URLhaus",
                    "timestamp": item.get("date_added")
                })
        return threats
    except Exception as e:
        print(f"URLhaus error: {e}")
        return []

def get_sample_threats():
    """Sample threats for demo when APIs are unavailable"""
    return [
        {"ioc": "192.168.1.100:4444", "type": "ip:port", "threat": "botnet_cc",
         "malware": "Emotet", "confidence": 90, "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "http://malicious-site.ru/payload.exe", "type": "url",
         "threat": "malware_download", "malware": ["ransomware"],
         "confidence": 85, "source": "URLhaus",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "10.0.0.55:8080", "type": "ip:port", "threat": "ransomware",
         "malware": "LockBit", "confidence": 95, "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "http://phishing-bank.xyz/login", "type": "url",
         "threat": "phishing", "malware": ["phishing"],
         "confidence": 75, "source": "URLhaus",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "evil-domain.com", "type": "domain", "threat": "malware_download",
         "malware": "TrickBot", "confidence": 88, "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "5f4dcc3b5aa765d61d8327deb882cf99", "type": "md5_hash",
         "threat": "malware", "malware": "Ryuk", "confidence": 92,
         "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "172.16.0.23:3389", "type": "ip:port", "threat": "exploit",
         "malware": "BlueKeep", "confidence": 78, "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "http://dropper.site/agent.dll", "type": "url",
         "threat": "malware_download", "malware": ["trojan"],
         "confidence": 82, "source": "URLhaus",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "bad-actor.net", "type": "domain", "threat": "botnet_cc",
         "malware": "Mirai", "confidence": 89, "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"ioc": "198.51.100.42:443", "type": "ip:port", "threat": "phishing",
         "malware": "AgentTesla", "confidence": 70, "source": "ThreatFox",
         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    ]

def get_all_threats():
    threats = []
    threats.extend(get_feodo_threats())
    threats.extend(get_urlhaus_threats())
    
    # Use sample data if APIs returned nothing
    if not threats:
        print("[*] APIs unavailable — using sample threat data")
        threats = get_sample_threats()
    
    for t in threats:
        t["fetched_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return threats
