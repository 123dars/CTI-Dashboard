import json

with open("enterprise-attack.json") as f:
    bundle = json.load(f)

objects = bundle["objects"]

malware = [o for o in objects if o["type"] == "malware"]
techniques = [o for o in objects if o["type"] == "attack-pattern"]
groups = [o for o in objects if o["type"] == "intrusion-set"]
mitigations = [o for o in objects if o["type"] == "course-of-action"]

def simplify(o):
    return {
        "id": o.get("id"),
        "name": o.get("name"),
        "description": o.get("description", "")[:300]
    }

data = {
    "malware": [simplify(o) for o in malware],
    "techniques": [simplify(o) for o in techniques],
    "groups": [simplify(o) for o in groups],
    "mitigations": [simplify(o) for o in mitigations]
}

with open("cti_data.json", "w") as f:
    json.dump(data, f, indent=2)

print("Malware:", len(malware))
print("Techniques:", len(techniques))
print("Groups:", len(groups))
print("Mitigations:", len(mitigations))
print("Saved to cti_data.json")
