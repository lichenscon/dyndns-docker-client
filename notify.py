import requests
import logging
import smtplib
from email.mime.text import MIMEText

def notify_ntfy(url, message):
    try:
        requests.post(url, data=message.encode("utf-8"), timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(f"ntfy-Notification fehlgeschlagen: {e}")

def notify_discord(webhook_url, message):
    try:
        data = {"content": message}
        requests.post(webhook_url, json=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(f"Discord-Notification fehlgeschlagen: {e}")

def notify_slack(webhook_url, message):
    try:
        data = {"text": message}
        requests.post(webhook_url, json=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(f"Slack-Notification fehlgeschlagen: {e}")

def notify_webhook(url, message):
    try:
        data = {"message": message}
        requests.post(url, json=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(f"Webhook-Notification fehlgeschlagen: {e}")

def notify_telegram(bot_token, chat_id, message):
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {"chat_id": chat_id, "text": message}
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        logging.getLogger("NOTIFY").warning(f"Telegram-Notification fehlgeschlagen: {e}")

def notify_email(cfg, subject, message, service_name=None):
    try:
        msg_text = f"[{service_name}] {message}" if service_name else message
        msg = MIMEText(msg_text)
        msg["Subject"] = subject
        msg["From"] = cfg["from"]
        msg["To"] = cfg["to"]
        port = cfg.get("smtp_port", 587)

        # Automatische Port-Logik
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
        # Verbesserte, menschenlesbare Fehlerausgabe
        err_str = str(e)
        if "[Errno -2]" in err_str:
            msg = "E-Mail-Notification fehlgeschlagen: SMTP-Server konnte nicht gefunden werden (Hostname falsch oder DNS-Problem)."
        elif "[Errno 111]" in err_str:
            msg = "E-Mail-Notification fehlgeschlagen: Verbindung zum SMTP-Server abgelehnt (falscher Server/Port oder Firewall)."
        elif "[Errno 110]" in err_str:
            msg = "E-Mail-Notification fehlgeschlagen: Timeout beim Verbindungsaufbau zum SMTP-Server."
        else:
            msg = f"E-Mail-Notification fehlgeschlagen: {e}"
        logging.getLogger("NOTIFY").warning(msg)

def send_notifications(config, level, message, subject=None, service_name=None):
    """
    config: dict aus config.yaml['notify']
    level: z.B. "ERROR", "CRITICAL", "UPDATE"
    message: Textnachricht
    subject: Optionaler Betreff für E-Mail
    service_name: Optional, Name des betroffenen Dienstes/Providers
    """
    if not config:
        return

    # ntfy
    ntfy_cfg = config.get("ntfy")
    if ntfy_cfg and ntfy_cfg.get("enabled") and level in ntfy_cfg.get("notify_on", []):
        notify_ntfy(ntfy_cfg["url"], message, service_name)

    # Discord
    discord_cfg = config.get("discord")
    if discord_cfg and discord_cfg.get("enabled") and level in discord_cfg.get("notify_on", []):
        notify_discord(discord_cfg["webhook_url"], message, service_name)

    # Slack
    slack_cfg = config.get("slack")
    if slack_cfg and slack_cfg.get("enabled") and level in slack_cfg.get("notify_on", []):
        notify_slack(slack_cfg["webhook_url"], message, service_name)

    # Webhook
    webhook_cfg = config.get("webhook")
    if webhook_cfg and webhook_cfg.get("enabled") and level in webhook_cfg.get("notify_on", []):
        notify_webhook(webhook_cfg["url"], message, service_name)

    # Telegram
    telegram_cfg = config.get("telegram")
    if telegram_cfg and telegram_cfg.get("enabled") and level in telegram_cfg.get("notify_on", []):
        notify_telegram(telegram_cfg["bot_token"], telegram_cfg["chat_id"], message, service_name)

    # Email
    email_cfg = config.get("email")
    if email_cfg and email_cfg.get("enabled") and level in email_cfg.get("notify_on", []):
        notify_email(email_cfg, subject or "DynDNS Client Benachrichtigung", message, service_name)