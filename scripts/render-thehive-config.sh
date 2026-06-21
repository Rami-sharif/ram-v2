#!/usr/bin/env bash
# Render TheHive config files that contain secrets, from their *.template
# counterparts, substituting values from .env. Output files are gitignored.
#
# Usage: ./scripts/render-thehive-config.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
CFG="$ROOT/thehive/config"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }

# Load only the keys we need (avoid sourcing arbitrary .env content)
get() { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-; }
ES_PW="$(get ELASTICSEARCH_PASSWORD)"
TH_SECRET="$(get THEHIVE_SECRET)"

[ -n "$ES_PW" ]     || { echo "ERROR: ELASTICSEARCH_PASSWORD empty in .env" >&2; exit 1; }
[ -n "$TH_SECRET" ] || { echo "ERROR: THEHIVE_SECRET empty in .env" >&2; exit 1; }

umask 077
sed "s|###ELASTICSEARCH_PASSWORD###|${ES_PW}|" "$CFG/index.conf.template"  > "$CFG/index.conf"
sed "s|###THEHIVE_SECRET###|${TH_SECRET}|"      "$CFG/secret.conf.template" > "$CFG/secret.conf"

echo "Rendered: thehive/config/index.conf, thehive/config/secret.conf (secrets not printed)"
