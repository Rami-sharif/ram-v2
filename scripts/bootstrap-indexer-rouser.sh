#!/usr/bin/env bash
# Create the least-privilege, READ-ONLY OpenSearch (Wazuh indexer) user the
# investigation agent uses to query alert history. Read-only on wazuh-alerts-*/
# wazuh-archives-* only; cannot write or touch security config.
#
# Writes WAZUH_INDEXER_RO_USER / WAZUH_INDEXER_RO_PASSWORD to .env (gitignored).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
IDX="${INDEXER_URL:-https://localhost:9200}"
RO_USER="ram_agent_ro"

ADMIN_PW="$(grep -E '^WAZUH_INDEXER_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
[ -n "$ADMIN_PW" ] || { echo "ERROR: WAZUH_INDEXER_PASSWORD missing in .env" >&2; exit 1; }
SEC="$IDX/_plugins/_security/api"
A=(-sk -u "admin:$ADMIN_PW" -H "Content-Type: application/json")

curl "${A[@]}" -X PUT "$SEC/roles/$RO_USER" -d '{
  "cluster_permissions": ["cluster_composite_ops_ro", "cluster:monitor/main"],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
    "allowed_actions": ["read", "indices_monitor"]
  }]
}' >/dev/null

RO_PW="$(openssl rand -hex 24)"
curl "${A[@]}" -X PUT "$SEC/internalusers/$RO_USER" \
  -d "{\"password\":\"$RO_PW\",\"description\":\"RAM v2 agent read-only (investigation tools)\"}" >/dev/null
curl "${A[@]}" -X PUT "$SEC/rolesmapping/$RO_USER" -d "{\"users\": [\"$RO_USER\"]}" >/dev/null

umask 077
if grep -q '^WAZUH_INDEXER_RO_PASSWORD=' "$ENV_FILE"; then
  sed -i "s|^WAZUH_INDEXER_RO_PASSWORD=.*|WAZUH_INDEXER_RO_PASSWORD=${RO_PW}|" "$ENV_FILE"
  sed -i "s|^WAZUH_INDEXER_RO_USER=.*|WAZUH_INDEXER_RO_USER=${RO_USER}|" "$ENV_FILE"
else
  printf '\nWAZUH_INDEXER_RO_USER=%s\nWAZUH_INDEXER_RO_PASSWORD=%s\n' "$RO_USER" "$RO_PW" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
echo "Created read-only indexer user '$RO_USER'; credentials written to .env (not printed)."
