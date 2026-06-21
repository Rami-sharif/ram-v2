#!/usr/bin/env bash
# Render Wazuh dashboard config that contains a secret (the Wazuh API password),
# from its template, using the value from .env. Output is gitignored.
#
# Usage: ./scripts/render-wazuh-config.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
CFG="$ROOT/wazuh/config/wazuh_dashboard"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }
API_PW="$(grep -E '^WAZUH_API_PASSWORD=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
[ -n "$API_PW" ] || { echo "ERROR: WAZUH_API_PASSWORD empty in .env" >&2; exit 1; }

umask 077
sed "s|###WAZUH_API_PASSWORD###|${API_PW}|" "$CFG/wazuh.yml.template" > "$CFG/wazuh.yml"
echo "Rendered: wazuh/config/wazuh_dashboard/wazuh.yml (secret not printed)"
