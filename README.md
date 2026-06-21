# RAM v2 — Phase 1

SOC alert-triage pipeline: **Wazuh alert → AI agent analysis (Gemini + VirusTotal) → TheHive case.**

Phase 1 scope is an end-to-end pipeline only. No memory layer, no triage router, no
multi-tenancy. Single company, single environment.

## Components
- **PostgreSQL + pgvector** — provisioned now, unused until a later phase.
- **TheHive 5** (+ Elasticsearch) — case management.
- **Wazuh** single-node (manager, indexer, dashboard) — alert source.
- **agent-service** (FastAPI) — webhook receiver, Gemini agent loop, TheHive client.

## Layout
```
docker-compose.yml      full stack
.env.example            env template (copy to .env, fill keys)
agent-service/          FastAPI service (webhook, agent, tools, thehive client)
```

## Setup
1. `cp .env.example .env` and fill in `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `POSTGRES_PASSWORD`.
2. `./scripts/render-thehive-config.sh` — render TheHive's secret config from templates.
3. `docker compose -f wazuh/generate-indexer-certs.yml run --rm generator` — generate Wazuh TLS certs.
4. `docker compose up -d` — bring up the stack.
5. `./scripts/bootstrap-thehive.sh` — create the org + agent service account, mint its
   API key into `.env`, and rotate the default admin password. Then
   `docker compose up -d agent-service` to load the key.

## Test the pipeline
```
curl -X POST http://localhost:8000/webhook/wazuh \
  -H 'Content-Type: application/json' --data @samples/wazuh_ssh_bruteforce.json
```
Produces a structured analysis and (when `THEHIVE_API_KEY` is set) a TheHive case.

## Ports
- TheHive UI/API `9000` (context path `/thehive`) · agent webhook `8000`
- Wazuh dashboard `8443` · Wazuh indexer `9200` · manager `1514/1515/55000`
- Postgres `127.0.0.1:5432`

## Status — Phase 1 COMPLETE
- [x] Step 1 — server inspection
- [x] Step 2a — host prep (Docker, Compose, git, sysctl)
- [x] Step 2b — Compose stack up & healthy
- [x] Step 3 — agent service receives test webhook & produces analysis
- [x] Step 4 — end-to-end: simulated alert → TheHive case
