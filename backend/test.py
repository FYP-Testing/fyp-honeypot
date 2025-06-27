import geoip2.database
reader = geoip2.database.Reader("/opt/fyp-honeypot/geoip/GeoLite2-City.mmdb")
ip = "8.8.8.8"
print(reader.city(ip).country.name)  # Should return 'United States'

