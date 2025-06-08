import pycurl
from io import BytesIO
import json
from datetime import datetime
import requests

# === CONFIGURATIONS ===
URLS = [
    "https://app.snyk.io/login",
    "https://artifactory.tc.lenovo.com",
    "http://coverity.tc.lenovo.com",
    "https://mobsf.scoe.lenovo.com/",
    "https://app.contrastsecurity.com",
    "https://bdba.scoe.lenovo.com/",
    "https://scoesoc.haloitsm.com/"
]

SUMO_ENDPOINT = "https://endpoint4.collection.sumologic.com/receiver/v1/http/ZaVnC4dhaV1KCl98A4c545eVY1JJTSScXBzUA6-9YSyoaWqD4TOZv-4IseNYKjr2096q2Or1sxW0DIGIiLPXVV1r017sWyNeziMmHUHIx3qNqtj5squQTw=="

# === FUNCTION TO MONITOR A SINGLE URL ===
def monitor_url(url):
    buffer = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(c.FOLLOWLOCATION, True)
    c.setopt(c.CONNECTTIMEOUT, 10)
    c.setopt(c.TIMEOUT, 20)

    try:
        c.perform()

        result = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "url": url,
            "status_code": c.getinfo(pycurl.RESPONSE_CODE),
            "success": 200 <= c.getinfo(pycurl.RESPONSE_CODE) < 300,
            "http.dns.time": round(c.getinfo(pycurl.NAMELOOKUP_TIME), 3),
            "http.connect.time": round(c.getinfo(pycurl.CONNECT_TIME) - c.getinfo(pycurl.NAMELOOKUP_TIME), 3),
            "http.ssl.time": round(c.getinfo(pycurl.APPCONNECT_TIME) - c.getinfo(pycurl.CONNECT_TIME), 3),
            "http.firstbyte.time": round(c.getinfo(pycurl.STARTTRANSFER_TIME) - c.getinfo(pycurl.APPCONNECT_TIME), 3),
            "http.download.time": round(c.getinfo(pycurl.TOTAL_TIME) - c.getinfo(pycurl.STARTTRANSFER_TIME), 3),
            "latency_total": round(c.getinfo(pycurl.TOTAL_TIME), 3)
        }

        print(json.dumps(result, indent=2))

        if SUMO_ENDPOINT:
            requests.post(SUMO_ENDPOINT, json=result)

    except pycurl.error as e:
        error_result = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "url": url,
            "success": False,
            "status_code": None,
            "error": str(e)
        }
        print(json.dumps(error_result, indent=2))
        if SUMO_ENDPOINT:
            requests.post(SUMO_ENDPOINT, json=error_result)

    finally:
        c.close()

# === LOOP URLS ===
if __name__ == "__main__":
    for url in URLS:
        monitor_url(url)
