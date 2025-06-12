import requests
import logging
import smtplib
import time
import os
from email.mime.text import MIMEText

def human_error_message(e, context=""):
    err_str = str(e)
    if "[Errno -2]" in err_str:
        return f"{context} fehlgeschlagen: Hostname nicht gefunden (DNS-Problem oder Tippfehler im Servernamen)."
    elif "[Errno 111]" in err_str:
        return f"{context} fehlgeschlagen: Verbindung abgelehnt (Server nicht erreichbar oder falscher Port)."
    elif "[Errno 110]" in err_str:
        return f"{context} fehlgeschlagen: Timeout beim Verbindungsaufbau."
    elif "Name or service not known" in err_str:
        return f"{context} fehlgeschlagen: Hostname nicht gefunden (DNS-Problem oder Tippfehler im Servernamen)."
    else:
        return f"{context} fehlgeschlagen: {e}"

def _cooldown_file(service):
    return f"/tmp/notify_cooldown_{service}.txt"

def _can_send_notification(service, cooldown_minutes):
    if not cooldown_minutes or cooldown_minutes <= 0:
        return True
    path = _cooldown_file(service)
    if not os.path.exists(path):
        return True
    with open(path, "r") as f:
        last = float(f.read())
    return (time.time() - last) > cooldown_minutes * 60

def _update_last_notification_time(service):
    with open(_cooldown_file(service), "w") as f:
        f.write(str(time.time()))

def notify_ntfy(url, message, service_name=None):
    try:
        msg = f"[{service_name}] {message}" if service_name else message
        requests.post(url, data=msg.encode("utf-8"), timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(human_error_message(e, "ntfy-Notification"))

def notify_discord(webhook_url, message, service_name=None):
    try:
        msg = f"[{service_name}] {message}" if service_name else message
        data = {"content": msg}
        requests.post(webhook_url, json=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(human_error_message(e, "Discord-Notification"))

def notify_slack(webhook_url, message, service_name=None):
    try:
        msg = f"[{service_name}] {message}" if service_name else message
        data = {"text": msg}
        requests.post(webhook_url, json=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(human_error_message(e, "Slack-Notification"))

def notify_webhook(url, message, service_name=None):
    try:
        msg = f"[{service_name}] {message}" if service_name else message
        data = {"message": msg}
        requests.post(url, json=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(human_error_message(e, "Webhook-Notification"))

def notify_telegram(bot_token, chat_id, message, service_name=None):
    try:
        msg = f"[{service_name}] {message}" if service_name else message
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {"chat_id": chat_id, "text": msg}
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(human_error_message(e, "Telegram-Notification"))

def notify_email(cfg, subject, message, service_name=None):
    try:
        msg_text = f"[{service_name}] {message}" if service_name else message
        msg = MIMEText(msg_text)
        msg["Subject"] = subject
        msg["From"] = cfg["from"]
        msg["To"] = cfg["to"]
        port = cfg.get("smtp_port", 587)
        if "smtp_ssl" in cfg:
            use_ssl = cfg["smtp_ssl"]
        elif port == 465:
            use_ssl = True
        else:
            use_ssl = False

        if "smtp_starttls" in cfg:
            use_starttls = cfg["smtp_starttls"]
        elif port == 587:
            use_starttls = True
        else:
            use_starttls = False

        if use_ssl:
            with smtplib.SMTP_SSL(cfg["smtp_server"], port) as server:
                if cfg.get("smtp_user") and cfg.get("smtp_pass"):
                    server.login(cfg["smtp_user"], cfg["smtp_pass"])
                server.sendmail(cfg["from"], [cfg["to"]], msg.as_string())
        else:
            with smtplib.SMTP(cfg["smtp_server"], port) as server:
                if use_starttls:
                    server.starttls()
                if cfg.get("smtp_user") and cfg.get("smtp_pass"):
                    server.login(cfg["smtp_user"], cfg["smtp_pass"])
                server.sendmail(cfg["from"], [cfg["to"]], msg.as_string())
    except Exception as e:
        logging.getLogger("NOTIFY").warning(human_error_message(e, "E-Mail-Notification"))

def reset_all_cooldowns():
    for service in ["ntfy", "discord", "slack", "webhook", "telegram", "email"]:
        try:
            os.remove(_cooldown_file(service))
        except FileNotFoundError:
            pass

def send_notifications(config, level, message, subject=None, service_name=None):
    # Cooldown-Reset bei Container-Start
    if config.get("reset_cooldown_on_start"):
        reset_all_cooldowns()
        # Nur einmal pro Start ausführen, z.B. durch ein globales Flag
        config["reset_cooldown_on_start"] = False

    if not config:
        return

    # ntfy
    ntfy_cfg = config.get("ntfy")
    if ntfy_cfg and ntfy_cfg.get("enabled") and level in ntfy_cfg.get("notify_on", []):
        cooldown = ntfy_cfg.get("cooldown", 0)
        if _can_send_notification("ntfy", cooldown):
            notify_ntfy(ntfy_cfg["url"], message, service_name)
            _update_last_notification_time("ntfy")

    # Discord
    discord_cfg = config.get("discord")
    if discord_cfg and discord_cfg.get("enabled") and level in discord_cfg.get("notify_on", []):
        cooldown = discord_cfg.get("cooldown", 0)
        if _can_send_notification("discord", cooldown):
            notify_discord(discord_cfg["webhook_url"], message, service_name)
            _update_last_notification_time("discord")

    # Slack
    slack_cfg = config.get("slack")
    if slack_cfg and slack_cfg.get("enabled") and level in slack_cfg.get("notify_on", []):
        cooldown = slack_cfg.get("cooldown", 0)
        if _can_send_notification("slack", cooldown):
            notify_slack(slack_cfg["webhook_url"], message, service_name)
            _update_last_notification_time("slack")

    # Webhook
    webhook_cfg = config.get("webhook")
    if webhook_cfg and webhook_cfg.get("enabled") and level in webhook_cfg.get("notify_on", []):
        cooldown = webhook_cfg.get("cooldown", 0)
        if _can_send_notification("webhook", cooldown):
            notify_webhook(webhook_cfg["url"], message, service_name)
            _update_last_notification_time("webhook")

    # Telegram
    telegram_cfg = config.get("telegram")
    if telegram_cfg and telegram_cfg.get("enabled") and level in telegram_cfg.get("notify_on", []):
        cooldown = telegram_cfg.get("cooldown", 0)
        if _can_send_notification("telegram", cooldown):
            notify_telegram(telegram_cfg["bot_token"], telegram_cfg["chat_id"], message, service_name)
            _update_last_notification_time("telegram")

    # Email
    email_cfg = config.get("email")
    if email_cfg and email_cfg.get("enabled") and level in email_cfg.get("notify_on", []):
        cooldown = email_cfg.get("cooldown", 0)
        if _can_send_notification("email", cooldown):
            notify_email(email_cfg, subject or "DynDNS Client Benachrichtigung", message, service_name)
            _update_last_notification_time("email")