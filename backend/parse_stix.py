import json

with open("enterprise-attack.json") as f:
    bundle = json.load(f)

objects = bundle["objects"]
print(f"Total objects: {len(objects)}")

for obj in objects[:5]:
    print(obj["type"], "-", obj.get("name", "no-name"))
