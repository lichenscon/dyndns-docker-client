import requests
import yaml
import time

def get_public_ip(ip_service):
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"Fehler beim Abrufen der öffentlichen IP: {e}")
        return None

def get_public_ipv6(ip_service="https://api64.ipify.org"):
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"Fehler beim Abrufen der öffentlichen IPv6: {e}")
        return None

def update_cloudflare(provider, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{provider['zone_id']}/dns_records/{provider['dns_record_id']}"
    headers = {
        "Authorization": f"Bearer {provider['api_token']}",
        "Content-Type": "application/json"
    }
    data = {
        "type": "A",
        "name": provider["record_name"],
        "content": ip,
        "proxied": provider.get("proxied", False)
    }
    resp = requests.patch(url, json=data, headers=headers)
    print(f"cloudflare response: {resp.text}")

def update_ipv64(provider, ip, ip6=None):
    url = provider['url']
    params = {}
    # Domain-Parameter
    if 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    # Authentifizierung
    auth = None
    headers = {}
    auth_method = provider.get('auth_method', 'token')
    token = provider.get('token')
    if auth_method == "token":
        params['key'] = token
    elif auth_method == "basic":
        auth = ('none', token)
    elif auth_method == "bearer":
        headers['Authorization'] = f"Bearer {token}"
    # IP-Parameter
    if ip:
        params['ip'] = ip
    if ip6:
        params['ip6'] = ip6
    response = requests.get(url, params=params, auth=auth, headers=headers)
    print(f"ipv64 response: {response.text}")

def update_dyndns2(provider, ip, ip6=None):
    url = provider['url']
    params = {}
    # Domain-Parameter
    if 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    # Authentifizierung
    auth = None
    headers = {}
    auth_method = provider.get('auth_method', 'token')
    token = provider.get('token')
    if auth_method == "token":
        params['key'] = token
    elif auth_method == "basic":
        auth = ('none', token)
    elif auth_method == "bearer":
        headers['Authorization'] = f"Bearer {token}"
    # IP-Parameter
    if ip:
        params['ip'] = ip
    if ip6:
        params['ip6'] = ip6
    response = requests.get(url, params=params, auth=auth, headers=headers)
    print(f"{provider.get('name', 'dyndns2')} response: {response.text}")

def update_provider(provider, ip, ip6=None):
    if provider.get("name") == "cloudflare":
        update_cloudflare(provider, ip)
        return
    if provider.get("name") == "ipv64":
        update_ipv64(provider, ip, ip6)
        return
    if provider.get("protocol") == "dyndns2":
        update_dyndns2(provider, ip, ip6)
        return
    # Standard-Provider-Logik
    url = provider['url']
    params = provider.get('params', {}).copy()
    params['ip'] = ip
    auth = None
    if 'username' in params and 'password' in params:
        auth = (params.pop('username'), params.pop('password'))
    response = requests.get(url, params=params, auth=auth)
    print(f"{provider.get('name', 'provider')} response: {response.text}")

def main():
    last_ip = None
    while True:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        timer = config.get('timer', 300)
        ip_service = config.get('ip_service', 'https://api.ipify.org')
        providers = config['providers']

        current_ip = get_public_ip(ip_service)
        current_ip6 = get_public_ipv6()  # oder eigenen Service in config.yaml
        if not current_ip:
            print("Konnte öffentliche IP nicht ermitteln. Warte auf nächsten Versuch.")
        elif current_ip != last_ip:
            print(f"Neue IP erkannt: {current_ip} (vorher: {last_ip}) – Update wird durchgeführt.")
            for provider in providers:
                update_provider(provider, current_ip, current_ip6)
            last_ip = current_ip
        else:
            print(f"IP unverändert ({current_ip}), kein Update notwendig.")

        time.sleep(timer)

if __name__ == "__main__":
    main()