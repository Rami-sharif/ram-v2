#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE="$ROOT/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env not found. Create it from .env.example and fill required values."
  echo "  cp .env.example .env"
  exit 1
fi

echo "[1/5] Rendering TheHive and Wazuh config files..."
./scripts/render-thehive-config.sh
./scripts/render-wazuh-config.sh

CERT_DIR="$ROOT/wazuh/config/wazuh_indexer_ssl_certs"
if [ ! -f "$CERT_DIR/root-ca.pem" ] || [ ! -f "$CERT_DIR/wazuh.indexer.pem" ]; then
  echo "[2/5] Generating Wazuh indexer certificates..."
  docker compose -f wazuh/generate-indexer-certs.yml run --rm generator
else
  echo "[2/5] Wazuh indexer certificates already exist, skipping generation."
fi

echo "[3/5] Starting Docker Compose stack..."
docker compose up -d --build

echo "[4/5] Waiting for agent-service to become healthy..."
for i in $(seq 1 12); do
  if curl -sSf http://localhost:8000/health >/dev/null 2>&1; then
    echo "agent-service is healthy."
    break
  fi
  echo "  waiting for agent-service... ($i/12)"
  sleep 5
  if [ "$i" -eq 12 ]; then
    echo "WARNING: agent-service did not become healthy within 60 seconds. Check docker compose ps and container logs."
  fi
done

if ! grep -q '^THEHIVE_API_KEY=' "$ENV_FILE" | grep -qv '^THEHIVE_API_KEY=$'; then
  echo "[5/5] TheHive API key is configured."
else
  echo "[5/5] TheHive API key is not configured. Run ./scripts/bootstrap-thehive.sh after the stack is up if needed."
fi

if ! grep -q '^WAZUH_INDEXER_RO_PASSWORD=' "$ENV_FILE" | grep -qv '^WAZUH_INDEXER_RO_PASSWORD=$'; then
  echo "Wazuh read-only indexer credentials are configured."
else
  echo "Wazuh read-only indexer user is not configured. Run ./scripts/bootstrap-indexer-rouser.sh after Wazuh indexer is ready."
fi

echo
 echo "Project startup complete."
 echo "Access agent-service at http://localhost:8000"
 echo "Access TheHive at http://localhost:9000"
