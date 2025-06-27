# app.py
from flask import Flask, jsonify, request
from elasticsearch import Elasticsearch
from flask_cors import CORS
import geoip2.database

app = Flask(__name__)
CORS(app)
app.secret_key = "change_this_to_secure_key"

# ElasticSearch and GeoIP setup
es = Elasticsearch("http://localhost:9200")
GEOIP_DB = "./geoip/GeoLite2-City.mmdb"
reader = geoip2.database.Reader("/opt/fyp-honeypot/geoip/GeoLite2-City.mmdb")

def ip_to_location(ip):
    try:
        response = reader.city(ip)
        return {
            "ip": ip,
            "country": response.country.name,
            "city": response.city.name,
            "lat": response.location.latitude,
            "lon": response.location.longitude
        }
    except:
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}

@app.route("/api/map_data")
def map_data():
    query = {"size": 100, "query": {"match_all": {}}}
    results = es.search(index="logstash-*", body=query)
    data = []
    for hit in results["hits"]["hits"]:
        src_ip = hit["_source"].get("src_ip")
        if src_ip:
            loc = ip_to_location(src_ip)
            loc["timestamp"] = hit["_source"].get("@timestamp")
            data.append(loc)
    return jsonify(data)

@app.route("/api/report_data")
def report_data():
    honeypot = request.args.get("honeypot", "*")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    query = {"size": 500, "query": {"bool": {"must": []}}}
    if honeypot != "*":
        query["query"]["bool"]["must"].append({"match": {"program": honeypot}})
    if start_date and end_date:
        query["query"]["bool"]["must"].append({"range": {"@timestamp": {"gte": start_date, "lte": end_date}}})
    results = es.search(index="logstash-*", body=query)
    return jsonify([hit["_source"] for hit in results["hits"]["hits"]])
