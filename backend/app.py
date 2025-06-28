# backend/app.py

from flask import Flask, jsonify, request
from elasticsearch import Elasticsearch
import geoip2.database
import os

app = Flask(__name__)

# === Configuration ===
ES_HOST = "http://localhost:9200"  # Update to your T-Pot IP if needed
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')

# === Elasticsearch connection ===
es = Elasticsearch(ES_HOST)

# === GeoIP Reader ===
geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# === Helper: Get GeoIP ===
def ip_to_geo(ip):
    try:
        response = geo_reader.city(ip)
        return {
            "lat": response.location.latitude,
            "lon": response.location.longitude,
            "city": response.city.name,
            "country": response.country.name
        }
    except:
        return {"lat": None, "lon": None, "city": None, "country": None}

# === Helper: Query Elasticsearch ===
def get_logs(honeypot_type, size=20):
    index_pattern = "logstash-*"
    query = {
        "size": size,
        "query": {
            "bool": {
                "must": []
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    if honeypot_type == "suricata":
        query["query"]["bool"]["must"].append({"match": {"event_type": "alert"}})
    elif honeypot_type == "cowrie":
        query["query"]["bool"]["must"].append({"match": {"eventid": "login.failed"}})
    elif honeypot_type == "honeytrap":
        query["query"]["bool"]["must"].append({"exists": {"field": "honeytrap.sensor.name"}})
    else:
        return []

    res = es.search(index=index_pattern, body=query)
    return [hit["_source"] for hit in res["hits"]["hits"]]

# === API: Live Attacks ===
@app.route("/api/live-attacks")
def live_attacks():
    logs = []
    for honeypot in ["suricata", "cowrie", "honeytrap"]:
        entries = get_logs(honeypot)
        for entry in entries:
            ip = (entry.get("src_ip") or
                  entry.get("src_ipaddr") or
                  entry.get("src_ip_address") or
                  entry.get("src_host") or
                  entry.get("remote_host"))
            if ip:
                geo = ip_to_geo(ip)
                logs.append({
                    "ip": ip,
                    "honeypot": honeypot,
                    "timestamp": entry.get("@timestamp"),
                    "geo": geo,
                })
    return jsonify(logs)

# === Index Test ===
@app.route("/")
def index():
    return "Hybrid Honeypot IDPS API Running"

# === Start Flask ===
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)