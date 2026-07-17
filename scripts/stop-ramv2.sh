#!/usr/bin/env bash
# Exit immediately on any command error (-e), on use of an unset variable (-u),
# and make a failure anywhere in a pipeline fail the whole pipeline (-o pipefail).
set -euo pipefail

# Resolve the repo root relative to this script's location so it can be run from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Make the docker compose command below resolve its compose file against the repo root.
cd "$ROOT"

echo "Stopping RAM v2 Docker Compose stack..."
# Stop and remove all containers, networks (and default volumes) defined by the compose stack.
docker compose down

echo "RAM v2 stopped."
