#!/bin/sh

# Zielpfad für die Konfiguration
CONFIG_FILE="/app/config/config.yaml"
EXAMPLE_CONFIG="/app/config.example.yaml"

# UID und GID des aktuellen Users im Container
CONTAINER_UID=$(id -u)
CONTAINER_GID=$(id -g)

# Falls config.yaml nicht existiert, kopiere die Beispiel-Config
if [ ! -f "$CONFIG_FILE" ]; then
  if [ -f "$EXAMPLE_CONFIG" ]; then
    cp "$EXAMPLE_CONFIG" "$CONFIG_FILE"
    echo "Beispiel-Konfiguration wurde als config.yaml angelegt."
  else
    echo "WARNUNG: Beispiel-Konfiguration ($EXAMPLE_CONFIG) nicht gefunden!"
  fi
fi

# Falls Datei existiert, Rechte prüfen und ggf. anpassen
if [ -f "$CONFIG_FILE" ]; then
  OWNER_UID=$(stat -c "%u" "$CONFIG_FILE")
  OWNER_GID=$(stat -c "%g" "$CONFIG_FILE")
  if [ "$OWNER_UID" != "$CONTAINER_UID" ] || [ "$OWNER_GID" != "$CONTAINER_GID" ]; then
    echo "Passe Besitzer von $CONFIG_FILE auf UID $CONTAINER_UID und GID $CONTAINER_GID an..."
    chown "$CONTAINER_UID:$CONTAINER_GID" "$CONFIG_FILE"
  fi
  chmod 644 "$CONFIG_FILE"
else
  echo "WARNUNG: $CONFIG_FILE existiert nicht!"
fi

exec python /app/update_dyndns.py
