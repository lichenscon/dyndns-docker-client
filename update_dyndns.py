import os
import time
import requests

DYNDNS_URL = os.getenv("DYNDNS_URL")
DYNDNS_USER = os.getenv("DYNDNS_USER")
DYNDNS_PASS = os.getenv("DYNDNS_PASS")
DYNDNS_APIKEY = os.getenv("DYNDNS_APIKEY")
DYNDNS_IP = os.getenv("DYNDNS_IP")
DYNDNS_HOSTNAME = os.getenv("DYNDNS_HOSTNAME")
UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "300"))  # Sekunden

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except Exception as e:
        print(f"Fehler beim Ermitteln der IP: {e}")
        return None

def update_dyndns(ip):
    headers = {}
    auth = None
    params = {
        "hostname": DYNDNS_HOSTNAME,
        "myip": ip
    }
    if DYNDNS_APIKEY:
        headers["Authorization"] = f"Bearer {DYNDNS_APIKEY}"
    elif DYNDNS_USER and DYNDNS_PASS:
        auth = (DYNDNS_USER, DYNDNS_PASS)
    else:
        print("Fehlende Zugangsdaten!")
        return

    try:
        r = requests.get(DYNDNS_URL, params=params, headers=headers, auth=auth)
        print(f"Update: {r.status_code} {r.text}")
    except Exception as e:
        print(f"Fehler beim DynDNS-Update: {e}")

if __name__ == "__main__":
    while True:
        ip = DYNDNS_IP or get_public_ip()
        if ip:
            update_dyndns(ip)
        else:
            print("Keine IP gefunden, Update übersprungen.")
        time.sleep(UPDATE_INTERVAL)
