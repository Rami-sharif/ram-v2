#!/usr/bin/env bash
# Create the least-privilege, READ-ONLY OpenSearch (Wazuh indexer) user the
# investigation agent uses to query alert history. Read-only on wazuh-alerts-*/
# wazuh-archives-* only; cannot write or touch security config.
#
# Writes WAZUH_INDEXER_RO_USER / WAZUH_INDEXER_RO_PASSWORD to .env (gitignored).
# Exit immediately on any command error (-e), on use of an unset variable (-u),
# and make a failure anywhere in a pipeline fail the whole pipeline (-o pipefail).
set -euo pipefail

# Resolve the repo root relative to this script's location so it can be run from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Path to the gitignored .env file that holds all secrets/credentials for the stack.
ENV_FILE="$ROOT/.env"
# OpenSearch (Wazuh indexer) base URL; overridable via INDEXER_URL, defaults to local HTTPS.
IDX="${INDEXER_URL:-https://localhost:9200}"
# Fixed username for the read-only service account this script creates.
RO_USER="ram_agent_ro"

# Pull the existing admin password out of .env (needed to authenticate as admin below).
ADMIN_PW="$(grep -E '^WAZUH_INDEXER_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
# Fail fast with a clear message if the admin password isn't configured yet.
[ -n "$ADMIN_PW" ] || { echo "ERROR: WAZUH_INDEXER_PASSWORD missing in .env" >&2; exit 1; }
# Base path for the OpenSearch security plugin's REST API.
SEC="$IDX/_plugins/_security/api"
# Shared curl flags: -s(k) skip TLS verify (self-signed local cert), -u admin basic auth, JSON content type.
A=(-sk -u "admin:$ADMIN_PW" -H "Content-Type: application/json")

# Create/replace the read-only role: cluster-level read-only ops plus read-only
# access scoped to only the Wazuh alert/archive index patterns (no write, no security config).
curl "${A[@]}" -X PUT "$SEC/roles/$RO_USER" -d '{
  "cluster_permissions": ["cluster_composite_ops_ro", "cluster:monitor/main"],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
    "allowed_actions": ["read", "indices_monitor"]
  }]
}' >/dev/null

# Generate a fresh random password for the new read-only account each run.
RO_PW="$(openssl rand -hex 24)"
# Create/replace the internal user with that generated password and a descriptive label.
curl "${A[@]}" -X PUT "$SEC/internalusers/$RO_USER" \
  -d "{\"password\":\"$RO_PW\",\"description\":\"RAM v2 agent read-only (investigation tools)\"}" >/dev/null
# Map the new user to the read-only role so the permissions actually take effect.
curl "${A[@]}" -X PUT "$SEC/rolesmapping/$RO_USER" -d "{\"users\": [\"$RO_USER\"]}" >/dev/null

# Restrict permissions on any files created from here on (the .env we're about to write/append).
umask 077
# If the RO password key already exists in .env, replace both it and the username in place...
if grep -q '^WAZUH_INDEXER_RO_PASSWORD=' "$ENV_FILE"; then
  sed -i "s|^WAZUH_INDEXER_RO_PASSWORD=.*|WAZUH_INDEXER_RO_PASSWORD=${RO_PW}|" "$ENV_FILE"
  sed -i "s|^WAZUH_INDEXER_RO_USER=.*|WAZUH_INDEXER_RO_USER=${RO_USER}|" "$ENV_FILE"
else
  # ...otherwise append fresh entries for both keys to the end of .env.
  printf '\nWAZUH_INDEXER_RO_USER=%s\nWAZUH_INDEXER_RO_PASSWORD=%s\n' "$RO_USER" "$RO_PW" >> "$ENV_FILE"
fi
# Re-assert restrictive permissions on .env since it now contains a new secret.
chmod 600 "$ENV_FILE"
# Confirm success without ever printing the actual credential values.
echo "Created read-only indexer user '$RO_USER'; credentials written to .env (not printed)."
