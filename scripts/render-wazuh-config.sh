#!/usr/bin/env bash
# Render Wazuh dashboard config that contains a secret (the Wazuh API password),
# from its template, using the value from .env. Output is gitignored.
#
# Usage: ./scripts/render-wazuh-config.sh
# Exit immediately on any command error (-e), on use of an unset variable (-u),
# and make a failure anywhere in a pipeline fail the whole pipeline (-o pipefail).
set -euo pipefail

# Resolve the repo root relative to this script's location so it can be run from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Path to the gitignored .env file holding the secret value to substitute in.
ENV_FILE="$ROOT/.env"
# Directory containing the Wazuh dashboard config template and its rendered output.
CFG="$ROOT/wazuh/config/wazuh_dashboard"

# Fail fast if .env doesn't exist — nothing to substitute the value from.
[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }
# Pull the Wazuh API password out of .env.
API_PW="$(grep -E '^WAZUH_API_PASSWORD=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
# Fail fast with a clear message if the password is missing/blank in .env.
[ -n "$API_PW" ] || { echo "ERROR: WAZUH_API_PASSWORD empty in .env" >&2; exit 1; }

# Restrict permissions on the file we're about to create, since it will contain a secret.
umask 077
# Substitute the placeholder token with the real API password to produce the rendered wazuh.yml.
sed "s|###WAZUH_API_PASSWORD###|${API_PW}|" "$CFG/wazuh.yml.template" > "$CFG/wazuh.yml"
# Confirm what was rendered without ever printing the actual secret value.
echo "Rendered: wazuh/config/wazuh_dashboard/wazuh.yml (secret not printed)"
