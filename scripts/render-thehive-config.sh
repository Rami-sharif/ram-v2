#!/usr/bin/env bash
# Render TheHive config files that contain secrets, from their *.template
# counterparts, substituting values from .env. Output files are gitignored.
#
# Usage: ./scripts/render-thehive-config.sh
# Exit immediately on any command error (-e), on use of an unset variable (-u),
# and make a failure anywhere in a pipeline fail the whole pipeline (-o pipefail).
set -euo pipefail

# Resolve the repo root relative to this script's location so it can be run from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Path to the gitignored .env file holding the secret values to substitute in.
ENV_FILE="$ROOT/.env"
# Directory containing the TheHive config templates and their rendered output.
CFG="$ROOT/thehive/config"

# Fail fast if .env doesn't exist — nothing to substitute values from.
[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found" >&2; exit 1; }

# Load only the keys we need (avoid sourcing arbitrary .env content)
# Helper: look up a single KEY=value line in .env and return just the value.
get() { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-; }
# Elasticsearch password used by TheHive's index config.
ES_PW="$(get ELASTICSEARCH_PASSWORD)"
# Play framework application secret used by TheHive's secret config.
TH_SECRET="$(get THEHIVE_SECRET)"

# Fail fast with a clear message if either required secret is missing/blank in .env.
[ -n "$ES_PW" ]     || { echo "ERROR: ELASTICSEARCH_PASSWORD empty in .env" >&2; exit 1; }
[ -n "$TH_SECRET" ] || { echo "ERROR: THEHIVE_SECRET empty in .env" >&2; exit 1; }

# Restrict permissions on the files we're about to create, since they will contain secrets.
umask 077
# Substitute the placeholder token with the real ES password to produce the rendered index.conf.
sed "s|###ELASTICSEARCH_PASSWORD###|${ES_PW}|" "$CFG/index.conf.template"  > "$CFG/index.conf"
# Substitute the placeholder token with the real app secret to produce the rendered secret.conf.
sed "s|###THEHIVE_SECRET###|${TH_SECRET}|"      "$CFG/secret.conf.template" > "$CFG/secret.conf"

# Confirm what was rendered without ever printing the actual secret values.
echo "Rendered: thehive/config/index.conf, thehive/config/secret.conf (secrets not printed)"
