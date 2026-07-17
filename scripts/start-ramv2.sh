#!/usr/bin/env bash
# Exit immediately on any command error (-e), on use of an unset variable (-u),
# and make a failure anywhere in a pipeline fail the whole pipeline (-o pipefail).
set -euo pipefail

# Resolve the repo root relative to this script's location so it can be run from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Make all relative paths below (docker compose files, ./scripts/...) resolve against the repo root.
cd "$ROOT"

# Path to the .env file that must exist and be filled in before the stack can start.
ENV_FILE="$ROOT/.env"

# Refuse to proceed without a configured .env; point the user at the example file to copy from.
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env not found. Create it from .env.example and fill required values."
  echo "  cp .env.example .env"
  exit 1
fi

echo "[1/5] Rendering TheHive and Wazuh config files..."
# Render TheHive's secret-bearing config files from their templates using .env values.
./scripts/render-thehive-config.sh
# Render the Wazuh dashboard's secret-bearing config file from its template.
./scripts/render-wazuh-config.sh

# Directory where the Wazuh indexer's TLS certificates are expected to live.
CERT_DIR="$ROOT/wazuh/config/wazuh_indexer_ssl_certs"
# Only generate certs if they're missing, so re-running this script doesn't regenerate/rotate them needlessly.
if [ ! -f "$CERT_DIR/root-ca.pem" ] || [ ! -f "$CERT_DIR/wazuh.indexer.pem" ]; then
  echo "[2/5] Generating Wazuh indexer certificates..."
  # Run the one-off cert-generator compose service and remove its container when done.
  docker compose -f wazuh/generate-indexer-certs.yml run --rm generator
else
  echo "[2/5] Wazuh indexer certificates already exist, skipping generation."
fi

echo "[3/5] Starting Docker Compose stack..."
# Bring up all services in the background, rebuilding images if their sources changed.
docker compose up -d --build

echo "[4/5] Waiting for agent-service to become healthy..."
# Poll the health endpoint up to 12 times (roughly one minute total) before giving up.
for i in $(seq 1 12); do
  # -sSf: silent but show errors, and fail (non-zero exit) on HTTP error status — used purely as a boolean check.
  if curl -sSf http://localhost:8000/health >/dev/null 2>&1; then
    echo "agent-service is healthy."
    # Health check passed; stop polling.
    break
  fi
  echo "  waiting for agent-service... ($i/12)"
  # Wait before the next poll attempt.
  sleep 5
  # After the final attempt, warn the operator instead of failing outright (service may just be slow).
  if [ "$i" -eq 12 ]; then
    echo "WARNING: agent-service did not become healthy within 60 seconds. Check docker compose ps and container logs."
  fi
done

# Report whether the TheHive API key has been provisioned yet (bootstrap-thehive.sh sets it).
if ! grep -q '^THEHIVE_API_KEY=' "$ENV_FILE" | grep -qv '^THEHIVE_API_KEY=$'; then
  echo "[5/5] TheHive API key is configured."
else
  echo "[5/5] TheHive API key is not configured. Run ./scripts/bootstrap-thehive.sh after the stack is up if needed."
fi

# Report whether the Wazuh read-only indexer user has been provisioned yet (bootstrap-indexer-rouser.sh sets it).
if ! grep -q '^WAZUH_INDEXER_RO_PASSWORD=' "$ENV_FILE" | grep -qv '^WAZUH_INDEXER_RO_PASSWORD=$'; then
  echo "Wazuh read-only indexer credentials are configured."
else
  echo "Wazuh read-only indexer user is not configured. Run ./scripts/bootstrap-indexer-rouser.sh after Wazuh indexer is ready."
fi

echo
 # Final status summary for the operator, with the URLs to reach the running services.
 echo "Project startup complete."
 echo "Access agent-service at http://localhost:8000"
 echo "Access TheHive at http://localhost:9000"
