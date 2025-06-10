import requests
import yaml
import time
import os

def get_public_ip(ip_service):
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"Fehler beim Abrufen der öffentlichen IP: {e}")
        return None

def update_provider(provider, ip):
    url = provider['url']
    params = provider['params'].copy()
    params['ip'] = ip
    auth = None
    if 'username' in params and 'password' in params:
        auth = (params.pop('username'), params.pop('password'))
    response = requests.get(url, params=params, auth=auth)
    print(f"{provider['name']} response: {response.text}")

def main():
    last_ip = None
    while True:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        timer = config.get('timer', 300)
        ip_service = config.get('ip_service', 'https://api.ipify.org')
        providers = config['providers']

        current_ip = get_public_ip(ip_service)
        if not current_ip:
            print("Konnte öffentliche IP nicht ermitteln. Warte auf nächsten Versuch.")
        elif current_ip != last_ip:
            print(f"Neue IP erkannt: {current_ip} (vorher: {last_ip}) – Update wird durchgeführt.")
            for provider in providers:
                update_provider(provider, current_ip)
            last_ip = current_ip
        else:
            print(f"IP unverändert ({current_ip}), kein Update notwendig.")

        time.sleep(timer)

if __name__ == "__main__":
    main()