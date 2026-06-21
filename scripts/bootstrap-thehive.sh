#!/usr/bin/env bash
# Bootstrap TheHive for RAM v2 (idempotent-ish, run once after first boot):
#   - create the ram-v2 organisation
#   - create a dedicated service account for the agent (profile: analyst)
#   - mint that account's API key  -> THEHIVE_API_KEY in .env
#   - rotate the default admin password from "secret" -> strong value in .env
#
# Secrets are written ONLY to .env (gitignored) and never printed.
# Requires: TheHive running and reachable; default admin still "secret".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
TH="${THEHIVE_PUBLIC_URL:-http://localhost:9000/thehive}"
ADMIN_DEFAULT='admin@thehive.local:secret'
SVC_LOGIN='agent@ram-v2.local'

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }

req() { # method path [json]  -> writes body to $BODY, sets $CODE
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    CODE=$(curl -s -o /tmp/th_boot.$$ -w '%{http_code}' -u "$ADMIN_DEFAULT" \
      -H "Content-Type: application/json" -X "$m" "$TH$p" -d "$d")
  else
    CODE=$(curl -s -o /tmp/th_boot.$$ -w '%{http_code}' -u "$ADMIN_DEFAULT" \
      -H "Content-Type: application/json" -X "$m" "$TH$p")
  fi
  BODY="$(cat /tmp/th_boot.$$)"; rm -f /tmp/th_boot.$$
}

echo "[1/5] Create organisation ram-v2"
req POST /api/v1/organisation '{"name":"ram-v2","description":"RAM v2 SOC triage"}'
{ [ "$CODE" = 201 ] || [ "$CODE" = 200 ] || echo "$BODY" | grep -q "already exists"; } \
  || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[2/5] Create service account $SVC_LOGIN (analyst)"
req POST /api/v1/user "{\"login\":\"$SVC_LOGIN\",\"name\":\"RAM v2 Agent\",\"organisation\":\"ram-v2\",\"profile\":\"analyst\"}"
{ [ "$CODE" = 201 ] || [ "$CODE" = 200 ] || echo "$BODY" | grep -q "already exists"; } \
  || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[3/5] Generate service-account API key"
req POST "/api/v1/user/$SVC_LOGIN/key/renew"
APIKEY="$BODY"
{ [ "$CODE" = 200 ] && [ -n "$APIKEY" ] && ! echo "$APIKEY" | grep -q '"type"'; } \
  || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[4/5] Rotate admin password"
NEWPW="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-28)"
req POST /api/v1/user/admin@thehive.local/password/set "{\"password\":\"$NEWPW\"}"
{ [ "$CODE" = 204 ] || [ "$CODE" = 200 ]; } || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[5/5] Write secrets to .env (not printed)"
umask 077
sed -i "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY=${APIKEY}|" "$ENV_FILE"
if grep -q '^THEHIVE_ADMIN_PASSWORD=' "$ENV_FILE"; then
  sed -i "s|^THEHIVE_ADMIN_PASSWORD=.*|THEHIVE_ADMIN_PASSWORD=${NEWPW}|" "$ENV_FILE"
else
  printf '\nTHEHIVE_ADMIN_USER=admin@thehive.local\nTHEHIVE_ADMIN_PASSWORD=%s\n' "$NEWPW" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

echo "Done. Restart the agent to pick up the key:  docker compose up -d agent-service"
