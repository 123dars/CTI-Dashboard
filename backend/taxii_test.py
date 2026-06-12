from taxii2client.v21 import Server

server = Server("https://cti-taxii.mitre.org/taxii2/")
api_root = server.api_roots[0]

for collection in api_root.collections:
    print(collection.title, "-", collection.id)



