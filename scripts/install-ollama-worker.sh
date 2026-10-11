#!/bin/bash
set -euo pipefail

# Called by the production updater after successful database migrations.
TP_WORKER_WEBROOT="${1:?Pass the deployment web root}"
TP_WORKER_STORAGE="${2:?Pass the private evidence storage root}"
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
  echo "Systemd is unavailable. Schedule scripts/ollama-worker.php using cron; see OLLAMA.md."
  exit 0
fi
if [ "$(id -u)" != 0 ]; then
  echo "Run the updater as root to install the automatic Ollama report worker."
  exit 1
fi
TP_WORKER_USER="${OLLAMA_WORKER_USER:-$(stat -c '%U' "$TP_WORKER_STORAGE")}"
TP_WORKER_GROUP="${OLLAMA_WORKER_GROUP:-$(stat -c '%G' "$TP_WORKER_STORAGE")}"
if [ "$TP_WORKER_USER" = root ]; then TP_WORKER_USER=www-data; fi
if [ "$TP_WORKER_GROUP" = root ]; then TP_WORKER_GROUP=www-data; fi
id "$TP_WORKER_USER" >/dev/null
getent group "$TP_WORKER_GROUP" >/dev/null
if [[ ! "$TP_WORKER_USER" =~ ^[a-zA-Z0-9_-]+$ || ! "$TP_WORKER_GROUP" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Invalid worker user or group."; exit 1
fi
if ! runuser -u "$TP_WORKER_USER" -g "$TP_WORKER_GROUP" -- test -r "$TP_WORKER_STORAGE/evidence"; then
  echo "The worker account cannot read private evidence. Set OLLAMA_WORKER_USER and OLLAMA_WORKER_GROUP to the web process account."; exit 1
fi
# These paths are interpolated into a unit, so require simple deployment paths.
if [[ ! "$TP_WORKER_WEBROOT" =~ ^/[a-zA-Z0-9_./-]+$ || ! "$TP_WORKER_STORAGE" =~ ^/[a-zA-Z0-9_./-]+$ ]]; then
  echo "Worker installation needs deployment paths without whitespace or unit syntax characters."; exit 1
fi

# Capture explicit DB overrides once, outside the public checkout. An existing
# operator-managed environment file is preserved on later updates.
install -d -m 0750 -o root -g "$TP_WORKER_GROUP" /etc/tiktokpredators
if [ ! -e /etc/tiktokpredators/ollama-worker.env ]; then
  (umask 077; : > /etc/tiktokpredators/ollama-worker.env)
  for TP_WORKER_KEY in DB_DSN DB_USER DB_PASS; do
    if [ "${!TP_WORKER_KEY+x}" = x ]; then
      TP_WORKER_VALUE="${!TP_WORKER_KEY}"
      if [[ "$TP_WORKER_VALUE" = *$'\n'* || "$TP_WORKER_VALUE" = *$'\r'* ]]; then
        echo "Database environment values must not contain line breaks."; exit 1
      fi
      TP_WORKER_VALUE="${TP_WORKER_VALUE//\\/\\\\}"
      TP_WORKER_VALUE="${TP_WORKER_VALUE//\"/\\\"}"
      printf '%s="%s"\n' "$TP_WORKER_KEY" "$TP_WORKER_VALUE" >> /etc/tiktokpredators/ollama-worker.env
    fi
  done
  chown root:"$TP_WORKER_GROUP" /etc/tiktokpredators/ollama-worker.env
  chmod 0640 /etc/tiktokpredators/ollama-worker.env
fi
sed -e "s|@USER@|$TP_WORKER_USER|g" -e "s|@GROUP@|$TP_WORKER_GROUP|g" \
  -e "s|@WEBROOT@|$TP_WORKER_WEBROOT|g" -e "s|@STORAGE@|$TP_WORKER_STORAGE|g" \
  "$TP_WORKER_WEBROOT/scripts/systemd/tiktokpredators-ollama.service" > /etc/systemd/system/tiktokpredators-ollama.service
chmod 0644 /etc/systemd/system/tiktokpredators-ollama.service
install -m 0644 "$TP_WORKER_WEBROOT/scripts/systemd/tiktokpredators-ollama.timer" /etc/systemd/system/tiktokpredators-ollama.timer
systemctl daemon-reload
systemctl enable --now tiktokpredators-ollama.timer
echo "Automatic Ollama report worker installed."
