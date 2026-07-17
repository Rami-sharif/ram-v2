#!/usr/bin/env bash
# Bootstrap TheHive for RAM v2 (idempotent-ish, run once after first boot):
#   - create the ram-v2 organisation
#   - create a dedicated service account for the agent (profile: analyst)
#   - mint that account's API key  -> THEHIVE_API_KEY in .env
#   - rotate the default admin password from "secret" -> strong value in .env
#
# Secrets are written ONLY to .env (gitignored) and never printed.
# Requires: TheHive running and reachable; default admin still "secret".
# Exit immediately on any command error (-e), on use of an unset variable (-u),
# and make a failure anywhere in a pipeline fail the whole pipeline (-o pipefail).
set -euo pipefail

# Resolve the repo root relative to this script's location so it can be run from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Path to the gitignored .env file that will receive the generated secrets.
ENV_FILE="$ROOT/.env"
# TheHive base URL; overridable via THEHIVE_PUBLIC_URL, defaults to the local compose address.
TH="${THEHIVE_PUBLIC_URL:-http://localhost:9000/thehive}"
# TheHive's known factory-default admin credentials, used only to bootstrap (then rotated below).
ADMIN_DEFAULT='admin@thehive.local:secret'
# Login identifier for the dedicated service account this script creates for the agent.
SVC_LOGIN='agent@ram-v2.local'

# Fail fast if .env doesn't exist yet — nothing to write secrets into.
[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }

req() { # method path [json]  -> writes body to $BODY, sets $CODE
  # Capture the positional args: HTTP method, API path, and optional JSON body.
  local m="$1" p="$2" d="${3:-}"
  # If a JSON body was given, send it as the request payload...
  if [ -n "$d" ]; then
    CODE=$(curl -s -o /tmp/th_boot.$$ -w '%{http_code}' -u "$ADMIN_DEFAULT" \
      -H "Content-Type: application/json" -X "$m" "$TH$p" -d "$d")
  else
    # ...otherwise issue the request with no body (e.g. for POST-with-no-payload endpoints).
    CODE=$(curl -s -o /tmp/th_boot.$$ -w '%{http_code}' -u "$ADMIN_DEFAULT" \
      -H "Content-Type: application/json" -X "$m" "$TH$p")
  fi
  # Read the response body from the temp file into $BODY, then clean up the temp file.
  BODY="$(cat /tmp/th_boot.$$)"; rm -f /tmp/th_boot.$$
}

echo "[1/5] Create organisation ram-v2"
# Ask TheHive to create the ram-v2 organisation that will own the agent's service account.
req POST /api/v1/organisation '{"name":"ram-v2","description":"RAM v2 SOC triage"}'
# Treat 201/200 as success, and also tolerate "already exists" so re-runs are safe (idempotent-ish).
{ [ "$CODE" = 201 ] || [ "$CODE" = 200 ] || echo "$BODY" | grep -q "already exists"; } \
  || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[2/5] Create service account $SVC_LOGIN (analyst)"
# Create the dedicated non-human account the agent will authenticate as, with the analyst profile.
req POST /api/v1/user "{\"login\":\"$SVC_LOGIN\",\"name\":\"RAM v2 Agent\",\"organisation\":\"ram-v2\",\"profile\":\"analyst\"}"
# Same tolerant success check: created fresh, or already present from a prior run.
{ [ "$CODE" = 201 ] || [ "$CODE" = 200 ] || echo "$BODY" | grep -q "already exists"; } \
  || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[3/5] Generate service-account API key"
# Renew (mint) the service account's API key; the response body IS the key itself.
req POST "/api/v1/user/$SVC_LOGIN/key/renew"
APIKEY="$BODY"
# Verify we got a 200 and a non-empty key that isn't actually a JSON error object (which would contain "type").
{ [ "$CODE" = 200 ] && [ -n "$APIKEY" ] && ! echo "$APIKEY" | grep -q '"type"'; } \
  || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[4/5] Rotate admin password"
# Generate a strong random password: base64 output, strip characters that are awkward in shell/URLs, trim to 28 chars.
NEWPW="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-28)"
# Replace the known default admin password with the freshly generated strong one.
req POST /api/v1/user/admin@thehive.local/password/set "{\"password\":\"$NEWPW\"}"
# TheHive may return 204 (no content) or 200 on success for this endpoint; either is fine.
{ [ "$CODE" = 204 ] || [ "$CODE" = 200 ]; } || { echo "  FAILED ($CODE): $BODY"; exit 1; }

echo "[5/5] Write secrets to .env (not printed)"
# Restrict permissions on any files created/modified from here on, since we're about to write secrets.
umask 077
# Store the newly minted API key, overwriting any previous placeholder/value.
sed -i "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY=${APIKEY}|" "$ENV_FILE"
# If an admin password entry already exists, replace it in place...
if grep -q '^THEHIVE_ADMIN_PASSWORD=' "$ENV_FILE"; then
  sed -i "s|^THEHIVE_ADMIN_PASSWORD=.*|THEHIVE_ADMIN_PASSWORD=${NEWPW}|" "$ENV_FILE"
else
  # ...otherwise append both the admin username and the new password as fresh entries.
  printf '\nTHEHIVE_ADMIN_USER=admin@thehive.local\nTHEHIVE_ADMIN_PASSWORD=%s\n' "$NEWPW" >> "$ENV_FILE"
fi
# Re-assert restrictive permissions on .env since it now contains new/updated secrets.
chmod 600 "$ENV_FILE"

# Remind the operator that the running agent-service container needs a restart to pick up the new key.
echo "Done. Restart the agent to pick up the key:  docker compose up -d agent-service"
