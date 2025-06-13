import sys
import os
import time
import requests
import yaml
import logging
from notify import send_notifications

config = None  # global, so update_provider can access it

def setup_logging(level_str):
    level = getattr(logging, level_str.upper(), logging.INFO)
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s --> %(message)s'))
    root.addHandler(handler)
    root.setLevel(level)

def log(msg, level="INFO", section="MAIN"):
    logger = logging.getLogger(section)
    level = level.upper()
    if level == "DEBUG":
        logger.debug(msg)
    elif level == "INFO":
        logger.info(msg)
    elif level == "WARNING":
        logger.warning(msg)
    elif level == "ERROR":
        logger.error(msg)
    elif level == "CRITICAL":
        logger.critical(msg)
    else:
        logger.info(msg)

def get_public_ip(ip_service):
    """
    Fetches the public IPv4 address from the given service.
    """
    try:
        response = requests.get(ip_service, timeout=10)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        log(f"Error fetching public IP: {e}", "ERROR")
        return None

def get_public_ipv6(ip_service="https://api64.ipify.org"):
    """
    Fetches the public IPv6 address from the given service.
    """
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        log(f"Error fetching public IPv6: {e}", "ERROR")
        return None

def get_cloudflare_zone_id(api_token, zone_name):
    """
    Retrieves the zone ID for a Cloudflare zone by name.
    """
    url = f"https://api.cloudflare.com/client/v4/zones?name={zone_name}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    if data.get("success") and data["result"]:
        return data["result"][0]["id"]
    raise Exception(f"Zone ID for {zone_name} not found: {data}")

def get_cloudflare_record_id(api_token, zone_id, record_name):
    """
    Retrieves the record ID for a DNS record in a Cloudflare zone.
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    if data.get("success") and data["result"]:
        return data["result"][0]["id"]
    raise Exception(f"DNS record ID for {record_name} not found: {data}")

def update_cloudflare(provider, ip, ip6=None):
    """
    Updates an A and optionally AAAA record at Cloudflare if the IP has changed.
    Returns "updated", "nochg" or False.
    """
    api_token = provider['api_token']
    zone = provider['zone']
    record_name = provider['record_name']
    zone_id = get_cloudflare_zone_id(api_token, zone)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    updated = False
    nochg = True

    # --- IPv4 (A-Record) ---
    if ip:
        url_a = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}&type=A"
        resp_a = requests.get(url_a, headers=headers)
        data_a = resp_a.json()
        log(f"Cloudflare GET A response: {data_a}", section="CLOUDFLARE")
        if data_a.get("success") and data_a["result"]:
            record_a = data_a["result"][0]
            if record_a["content"] == ip:
                log(f"No update needed (IPv4 already set: {ip}).", "INFO", section="CLOUDFLARE")
            else:
                url_patch = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_a['id']}"
                data_patch = {
                    "type": "A",
                    "name": record_name,
                    "content": ip
                }
                resp_patch = requests.patch(url_patch, json=data_patch, headers=headers)
                log(f"Cloudflare PATCH A response: {resp_patch.text}", section="CLOUDFLARE")
                if resp_patch.ok:
                    updated = True
                    nochg = False
        else:
            log(f"A record {record_name} not found or error: {data_a}", "ERROR", section="CLOUDFLARE")
            nochg = False

    # --- IPv6 (AAAA-Record) ---
    if ip6:
        url_aaaa = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}&type=AAAA"
        resp_aaaa = requests.get(url_aaaa, headers=headers)
        data_aaaa = resp_aaaa.json()
        log(f"Cloudflare GET AAAA response: {data_aaaa}", section="CLOUDFLARE")
        if data_aaaa.get("success") and data_aaaa["result"]:
            record_aaaa = data_aaaa["result"][0]
            if record_aaaa["content"] == ip6:
                log(f"No update needed (IPv6 already set: {ip6}).", "INFO", section="CLOUDFLARE")
            else:
                url_patch = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_aaaa['id']}"
                data_patch = {
                    "type": "AAAA",
                    "name": record_name,
                    "content": ip6
                }
                resp_patch = requests.patch(url_patch, json=data_patch, headers=headers)
                log(f"Cloudflare PATCH AAAA response: {resp_patch.text}", section="CLOUDFLARE")
                if resp_patch.ok:
                    updated = True
                    nochg = False
        else:
            log(f"AAAA record {record_name} not found or error: {data_aaaa}", "ERROR", section="CLOUDFLARE")
            nochg = False

    if updated:
        return "updated"
    if nochg:
        return "nochg"
    return False

def update_ipv64(provider, ip, ip6=None):
    """
    Updates a record at ipv64.net.
    Supports IPv4 and IPv6.
    Returns "updated", "nochg" or False.
    The URL is hardcoded.
    """
    url = "https://ipv64.net/nic/update"
    params = {}
    if 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
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
    if ip:
        params['ip'] = ip
    if ip6:
        params['ip6'] = ip6
    response = requests.get(url, params=params, auth=auth, headers=headers)
    log(f"ipv64 response: {response.text}", section="IPV64")
    resp_text = response.text.lower().strip()
    if "overcommited" in resp_text or response.status_code == 403:
        log("Update interval at ipv64.net exceeded! Update limit reached.", "ERROR", section="IPV64")
        return False
    if "nochg" in resp_text or "no change" in resp_text:
        log("No update needed (nochg).", "INFO", section="IPV64")
        return "nochg"
    if "good" in resp_text or "success" in resp_text:
        return "updated"
    log(f"ipv64 update failed: {response.text}", "ERROR", section="IPV64")
    return False

def update_dyndns2(provider, ip, ip6=None):
    """
    Updates a DynDNS2-compatible provider (e.g. DuckDNS, NoIP, Dynu).
    Supports IPv4 and IPv6.
    Returns "updated", "nochg" or False.
    """
    url = provider['url']
    params = {}
    if 'hostname' in provider:
        params['hostname'] = provider['hostname']
    elif 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    if ip:
        params['myip'] = ip
    if ip6:
        params['myipv6'] = ip6

    auth = None
    headers = {}
    auth_method = provider.get('auth_method', 'token')
    token = provider.get('token')
    username = provider.get('username')
    password = provider.get('password')

    if auth_method == "basic":
        auth = (username or token, password or token or "x")
    elif auth_method == "bearer":
        headers['Authorization'] = f"Bearer {token}"
    else:
        if 'key' in provider:
            params['key'] = provider['key']
        elif 'user' in provider:
            params['user'] = provider['user']
        elif 'token' in provider:
            params['token'] = provider['token']
        else:
            params['key'] = token

    response = requests.get(url, params=params, auth=auth, headers=headers)
    provider_name = provider.get('name', 'dyndns2')
    log(f"[{provider_name}] response: {response.text}", section="DYNDNS2")

    resp_text = response.text.lower().strip()
    if "nochg" in resp_text:
        log(f"[{provider_name}] No update needed (nochg).", "INFO", section="DYNDNS2")
        return "nochg"
    elif any(success in resp_text for success in ["good", "success"]):
        return "updated"
    else:
        log(
            f"[{provider_name}] DynDNS2 update failed: {response.text}",
            "ERROR",
            section="DYNDNS2"
        )
        return False

def validate_config(config):
    """
    Checks config.yaml for required fields and prints errors with line numbers.
    Returns True if everything is fine, otherwise False.
    """
    required_top = ["timer", "providers"]
    allowed_protocols = ("cloudflare", "ipv64", "dyndns2")

    # Top-level required keys
    for key in required_top:
        if key not in config:
            log(f"Missing key '{key}' in config.yaml.", "ERROR")
            return False

    # Providers must be a non-empty list
    if not isinstance(config["providers"], list) or not config["providers"]:
        log("The field 'providers' must be a non-empty list.", "ERROR")
        return False

    # Require at least one IP service (IPv4 or IPv6)
    if "ip_service" not in config and "ip6_service" not in config:
        log("Missing 'ip_service' or 'ip6_service' in config.yaml. At least one is required.", "ERROR")
        return False

    for idx, provider in enumerate(config["providers"]):
        pname = provider.get('name', f'#{idx+1}')
        # Protocol existence and validity
        if "protocol" not in provider:
            log(f"Missing field 'protocol' in provider {pname} in config.yaml.", "ERROR")
            return False
        if provider["protocol"] not in allowed_protocols:
            log(
                f"Invalid field 'protocol' ('{provider['protocol']}') in provider {pname} in config.yaml. "
                f"Allowed: {', '.join(allowed_protocols)}.",
                "ERROR"
            )
            return False

        # Protocol-specific required fields
        if provider["protocol"] == "cloudflare":
            for field in ("zone", "api_token", "record_name"):
                if field not in provider:
                    log(f"Missing field '{field}' in Cloudflare provider {pname} in config.yaml.", "ERROR")
                    return False
        elif provider["protocol"] in ("dyndns2", "ipv64"):
            if "url" not in provider:
                log(f"Missing field 'url' in provider {pname} in config.yaml.", "ERROR")
                return False
            # Require one of hostname/domain/host
            if not any(k in provider for k in ("hostname", "domain", "host")):
                log(f"Missing hostname/domain/host in provider {pname} in config.yaml.", "ERROR")
                return False
            # Require authentication fields: username+password or token
            has_userpass = "username" in provider and "password" in provider
            has_token = "token" in provider
            if not (has_userpass or has_token):
                log(f"Missing authentication fields (username+password or token) in provider {pname} in config.yaml.", "ERROR")
                return False

    return True

def _ip_cache_file(ip_version):
    return f"/tmp/last_ip_{ip_version}.txt"

def load_last_ip(ip_version):
    try:
        with open(_ip_cache_file(ip_version), "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def save_last_ip(ip_version, ip):
    try:
        with open(_ip_cache_file(ip_version), "w") as f:
            f.write(str(ip) if ip is not None else "")
    except Exception as e:
        log(f"Error saving last IP ({ip_version}): {e}", "ERROR", section="MAIN")

def update_provider(provider, ip, ip6=None, log_success_if_nochg=True, old_ip=None, old_ip6=None):
    """
    Selects the appropriate update function for the provider based on the protocol.
    Logs the result and returns True (update/nochg) or False (error).
    """
    try:
        provider_name = provider.get("name", "PROVIDER")
        protocol = provider.get("protocol", "unknown")
        # Cloudflare
        if protocol == "cloudflare":
            result = update_cloudflare(provider, ip, ip6)
            if result == "updated":
                msg = f"Provider '{provider_name}' updated successfully. New IP: {ip}"
                if old_ip is not None:
                    msg += f" (previous: {old_ip})"
                log(msg, "INFO", section="CLOUDFLARE")
                send_notifications(
                    config.get("notify"),
                    "UPDATE",
                    msg,
                    subject=f"DynDNS Update: {provider_name}",
                    service_name=provider_name
                )
            elif result == "nochg":
                if log_success_if_nochg:
                    log(f"Provider '{provider_name}' was already up to date, no update performed.", "INFO", section="CLOUDFLARE")
            else:
                error_msg = f"Provider '{provider_name}' update failed. See previous log for details."
                log(error_msg, "ERROR", section="CLOUDFLARE")
                send_notifications(
                    config.get("notify"),
                    "ERROR",
                    f"Update failed for provider '{provider_name}' (Cloudflare). See logs for details.",
                    subject=f"DynDNS Error: {provider_name}",
                    service_name=provider_name
                )
            return result == "updated" or (log_success_if_nochg and result == "nochg")
        # ipv64
        if protocol == "ipv64":
            result = update_ipv64(provider, ip, ip6)
            if result == "updated":
                msg = f"Provider '{provider_name}' updated successfully. New IP: {ip}"
                if old_ip is not None:
                    msg += f" (previous: {old_ip})"
                log(msg, "INFO", section="IPV64")
                send_notifications(
                    config.get("notify"),
                    "UPDATE",
                    msg,
                    subject=f"DynDNS Update: {provider_name}",
                    service_name=provider_name
                )
            elif result == "nochg":
                if log_success_if_nochg:
                    log(f"Provider '{provider_name}' was already up to date, no update performed.", "INFO", section="IPV64")
            else:
                error_msg = f"Provider '{provider_name}' update failed. See previous log for details."
                log(error_msg, "ERROR", section="IPV64")
                send_notifications(
                    config.get("notify"),
                    "ERROR",
                    f"Update failed for provider '{provider_name}' (ipv64). See logs for details.",
                    subject=f"DynDNS Error: {provider_name}",
                    service_name=provider_name
                )
            return result == "updated" or (log_success_if_nochg and result == "nochg")
        # dyndns2
        if protocol == "dyndns2":
            result = update_dyndns2(provider, ip, ip6)
            if result == "updated":
                msg = f"Provider '{provider_name}' updated successfully. New IP: {ip}"
                if old_ip is not None:
                    msg += f" (previous: {old_ip})"
                log(msg, "INFO", section="DYNDNS2")
                send_notifications(
                    config.get("notify"),
                    "UPDATE",
                    msg,
                    subject=f"DynDNS Update: {provider_name}",
                    service_name=provider_name
                )
            elif result == "nochg":
                if log_success_if_nochg:
                    log(f"Provider '{provider_name}' was already up to date, no update performed.", "INFO", section="DYNDNS2")
            else:
                error_msg = f"Provider '{provider_name}' update failed. See previous log for details."
                log(error_msg, "ERROR", section="DYNDNS2")
                send_notifications(
                    config.get("notify"),
                    "ERROR",
                    f"Update failed for provider '{provider_name}' (dyndns2). See logs for details.",
                    subject=f"DynDNS Error: {provider_name}",
                    service_name=provider_name
                )
            return result == "updated" or (log_success_if_nochg and result == "nochg")
    except Exception as e:
        provider_name = provider.get("name", "PROVIDER")
        protocol = provider.get("protocol", "unknown")
        error_msg = f"Update for provider '{provider_name}' ({protocol}) failed: {e}"
        log(error_msg, "ERROR", section=provider_name.upper())
        send_notifications(
            config.get("notify"),
            "ERROR",
            error_msg,
            subject=f"DynDNS Error: {provider_name}",
            service_name=provider_name
        )
        return False

def main():
    global config
    config_path = 'config/config.yaml'
    if not os.path.exists(config_path):
        setup_logging("INFO")
        log("config/config.yaml not found! Please provide your own configuration or copy config.example.yaml.\n"
            "See instructions in the repository: https://github.com/alex-1987/dyndns-docker-client\n"
            "Example for Docker Compose:\n"
            "  volumes:\n"
            "    - ./config:/app/config\n"
            "and place your config.yaml in the ./config directory on the host.",
            "CRITICAL"
        )
        sys.exit(1)
    with open(config_path, 'r') as f:
        try:
            config = yaml.safe_load(f)
        except Exception as e:
            setup_logging("INFO")
            log(f"Error loading config.yaml: {e}", "ERROR")
            sys.exit(1)
    loglevel = config.get("loglevel", "INFO")
    setup_logging(loglevel)
    last_config_mtime = os.path.getmtime(config_path)
    if not config or not isinstance(config, dict):
        log(
            "config.yaml is empty or invalid! Please check the file and refer to config.example.yaml.\n"
            "See instructions in the repository: https://github.com/alex-1987/dyndns-docker-client",
            "CRITICAL"
        )
        sys.exit(1)
    if "providers" not in config or not isinstance(config["providers"], list) or not config["providers"]:
        log(
            "config.yaml does not contain any providers! Please add at least one provider under 'providers:'.\n"
            "See instructions and examples in the repository: https://github.com/alex-1987/dyndns-docker-client",
            "CRITICAL"
        )
        sys.exit(1)
    if not validate_config(config):
        log("Configuration invalid. Program will exit.", "CRITICAL")
        sys.exit(1)
    timer = config.get('timer', 300)
    ip_service = config.get('ip_service', 'https://api.ipify.org')
    ip6_service = config.get('ip6_service', None)
    providers = config['providers']

    log(f"Testing reachability of ip_service: {ip_service}", section="MAIN")
    test_ip = get_public_ip(ip_service) if ip_service else None
    test_ip6 = get_public_ipv6(ip6_service) if ip6_service else None
    if not test_ip and not test_ip6:
        log("Program will exit because neither ip_service nor ip6_service is reachable.", "CRITICAL")
        return
    if test_ip:
        log(f"ip_service reachable. Public IP: {test_ip}", section="MAIN")
    if test_ip6:
        log(f"ip6_service reachable. Public IPv6: {test_ip6}", section="MAIN")

    # --- PATCH: skip_update_on_startup ---
    skip_on_startup = config.get("skip_update_on_startup", False)
    last_ip = load_last_ip("v4")
    last_ip6 = load_last_ip("v6")
    ip_changed = (test_ip != last_ip) if test_ip else False
    ip6_changed = (test_ip6 != last_ip6) if test_ip6 else False

    if skip_on_startup and not ip_changed and not ip6_changed:
        log("IP has not changed since last run. No provider updates needed on startup.", "INFO", section="MAIN")
        # IPs trotzdem speichern, falls sie vorher noch nicht gespeichert waren
        save_last_ip("v4", test_ip)
        save_last_ip("v6", test_ip6)
        last_ip = test_ip
        last_ip6 = test_ip6
    else:
        log("Starting initial update run for all providers...", section="MAIN")
        failed_providers = []
        for provider in providers:
            result = update_provider(provider, test_ip, test_ip6)
            section = provider.get('name', 'PROVIDER').upper()
            if not (result or result == "nochg"):
                log(f"Provider '{provider.get('name')}' could not be updated initially.", "WARNING", section=section)
                failed_providers.append(provider)
        save_last_ip("v4", test_ip)
        save_last_ip("v6", test_ip6)
        last_ip = test_ip
        last_ip6 = test_ip6
    # --- END PATCH ---

    elapsed = 0
    check_interval = 2  # Seconds, how often to check for config changes

    log(f"Next run in {timer} seconds...", section="MAIN")

    while True:
        time.sleep(check_interval)
        elapsed += check_interval

        # Check if config has changed
        current_mtime = os.path.getmtime(config_path)
        if current_mtime != last_config_mtime:
            log("Change in config.yaml detected. Reloading configuration and starting a new run.", section="MAIN")
            with open(config_path, 'r') as f:
                try:
                    config = yaml.safe_load(f)
                except Exception as e:
                    log(f"Error loading config.yaml after change: {e}\nPlease check the file and refer to config.example.yaml.", "ERROR")
                    continue
            if not validate_config(config):
                log("Configuration invalid after change. Waiting for next change...", "ERROR")
                continue
            timer = config.get('timer', 300)
            ip_service = config.get('ip_service', 'https://api.ipify.org')
            ip6_service = config.get('ip6_service', None)
            providers = config['providers']
            last_config_mtime = current_mtime
            current_ip = get_public_ip(ip_service) if ip_service else None
            current_ip6 = get_public_ipv6(ip6_service) if ip6_service else None
            if current_ip:
                log(f"Current public IP: {current_ip}", section="MAIN")
            if current_ip6:
                log(f"Current public IPv6: {current_ip6}", section="MAIN")
            failed_providers = []
            for provider in providers:
                result = update_provider(provider, current_ip, current_ip6)
                section = provider.get('name', 'PROVIDER').upper()
                if not (result or result == "nochg"):
                    log(f"Provider '{provider.get('name')}' could not be updated after config change.", "WARNING", section=section)
                    failed_providers.append(provider)
            last_ip = current_ip
            last_ip6 = current_ip6
            elapsed = 0
            log(f"Next run in {timer} seconds...", section="MAIN")
            continue

        # Timer-based update as usual
        if elapsed >= timer:
            current_ip = get_public_ip(ip_service) if ip_service else None
            current_ip6 = get_public_ipv6(ip6_service) if ip6_service else None
            if current_ip:
                log(f"Current public IP: {current_ip}", section="MAIN")
            if current_ip6:
                log(f"Current public IPv6: {current_ip6}", section="MAIN")
            # Check for IP change or failed providers
            ip_changed = (current_ip != last_ip) if ip_service else False
            ip6_changed = (current_ip6 != last_ip6) if ip6_service else False
            if ip_changed or ip6_changed or failed_providers:
                if ip_changed:
                    log(f"New IP detected: {current_ip} (previous: {last_ip}) – update will be performed.", section="MAIN")
                if ip6_changed:
                    log(f"New IPv6 detected: {current_ip6} (previous: {last_ip6}) – update will be performed.", section="MAIN")
                # Check all providers, always retry failed providers!
                retry_providers = failed_providers.copy()
                failed_providers = []
                for provider in providers:
                    # Retry if provider was in failed_providers or IP changed
                    if provider in retry_providers or ip_changed or ip6_changed:
                        result = update_provider(provider, current_ip, current_ip6)
                        section = provider.get('name', 'PROVIDER').upper()
                        if not (result or result == "nochg"):
                            failed_providers.append(provider)
                last_ip = current_ip
                last_ip6 = current_ip6
                elapsed = 0
                log(f"Next run in {timer} seconds...", section="MAIN")
            else:
                if current_ip:
                    log(f"IP unchanged ({current_ip}), no update needed.", section="MAIN")
                if current_ip6:
                    log(f"IPv6 unchanged ({current_ip6}), no update needed.", section="MAIN")
                elapsed = 0
                log(f"Next run in {timer} seconds...", section="MAIN")

if __name__ == "__main__":
    main()
