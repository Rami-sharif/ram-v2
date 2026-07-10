#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Stopping RAM v2 Docker Compose stack..."
docker compose down

echo "RAM v2 stopped."
