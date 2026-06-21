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
2. `docker compose up -d` — bring up the stack.
3. Log into TheHive, generate an API key, paste into `.env` as `THEHIVE_API_KEY`, then
   `docker compose up -d agent-service` to pick it up.

## Status
- [x] Step 1 — server inspection
- [x] Step 2a — host prep (Docker, Compose, git, sysctl)
- [ ] Step 2b — Compose stack up & healthy
- [ ] Step 3 — agent service receives test webhook & produces analysis
- [ ] Step 4 — end-to-end: simulated alert → TheHive case
