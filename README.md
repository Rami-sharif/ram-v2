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
2. Set the Wazuh credential vars in `.env` (`WAZUH_INDEXER_PASSWORD`,
   `WAZUH_DASHBOARD_PASSWORD`, `WAZUH_API_PASSWORD`) — strong values, not the demo defaults.
3. `./scripts/render-thehive-config.sh` — render TheHive's secret config from templates.
4. `./scripts/render-wazuh-config.sh` — render the dashboard's API config from template.
5. `docker compose -f wazuh/generate-indexer-certs.yml run --rm generator` — generate Wazuh TLS certs.
6. `docker compose up -d` — bring up the stack.
7. `./scripts/bootstrap-thehive.sh` — create the org + agent service account, mint its
   API key into `.env`, and rotate the default admin password. Then
   `docker compose up -d agent-service` to load the key.

> **Wazuh demo passwords**: the indexer (`admin`, `kibanaserver`) and API (`wazuh-wui`)
> users ship with public demo passwords. After first boot, rotate them: update the bcrypt
> hashes in `wazuh/config/wazuh_indexer/internal_users.yml` (use the indexer's `hash.sh`),
> apply with `securityadmin.sh -t internalusers`, change `wazuh-wui` via the Wazuh API, and
> set the matching `WAZUH_*` values in `.env`. The unused demo users (kibanaro, logstash,
> readall, snapshotrestore) still hold defaults — remove or rotate them in a later pass.

## Test the pipeline
```
curl -X POST http://localhost:8000/webhook/wazuh \
  -H 'Content-Type: application/json' --data @samples/wazuh_ssh_bruteforce.json
```
Produces a structured analysis and (when `THEHIVE_API_KEY` is set) a TheHive case.

## Investigation agent (read-only, bounded tool choice)
The agent investigates each alert by freely choosing tools from a **read-only allowlist**
(it cannot act), capped at `AGENT_MAX_ITERATIONS` (default 8); the loop ends on
`submit_analysis` or a forced submit at the cap (the alert is never dropped). Every tool
call is logged with name, args, and the model's `reason`. Tools live in a registry
(`app/tools/`) — adding one is a single `register(Tool(...))`.

Tools (all read-only): `virustotal_ip_lookup`, `lookup_file_hash`, `lookup_domain`,
`get_related_logs`, `get_host_alert_history`, `get_user_activity`, `get_full_log_context`
(Wazuh **Indexer** queries via the least-privilege `ram_agent_ro` OpenSearch user),
and `search_memory`. Results are size-capped; tool failures degrade gracefully.

The least-privilege indexer user is created by `scripts/bootstrap-indexer-rouser.sh`
(read-only on `wazuh-alerts-*`; write/security calls rejected). Output shape is unchanged,
so the triage router below is unaffected.

## Triage router (deterministic, no LLM)
After the agent produces its analysis, a fixed-code router decides the action by
`severity_score` (0–100, env thresholds) and dedups by `agent_name|rule_id|source_ip`:
- **score < `TRIAGE_MEDIUM_THRESHOLD`** → auto-close (no case; memory + audit log only)
- **medium ≤ score < `TRIAGE_HIGH_THRESHOLD`** → open `needs-review` case
- **score ≥ `TRIAGE_HIGH_THRESHOLD`** → case + `flag` (escalated)
- **dedup**: within `TRIAGE_DEDUP_WINDOW_HOURS` a repeat key suppresses the new case and
  increments `occurrence_count` on the existing one. Alerts with **no source_ip are never
  deduped** (always create a case) to avoid falsely merging unrelated no-IP events.

Memory write-back is independent of routing — auto-closed and deduped alerts are still
stored. Every decision is logged with its reason (`TRIAGE decision …`). Dedup state lives
in `triage_dedup` (`db/002_triage_dedup.sql`).

## Memory operator API (`/memory`)
Privileged endpoints for inspecting/editing/deleting the semantic memory that drives
analysis. **All require** `Authorization: Bearer $OPERATOR_API_TOKEN` (in `.env`).
- `GET /memory` — filter by `agent_name`/`source_ip`/`rule_id`/`date_from`/`date_to` (+ `limit`/`offset`)
- `POST /memory/search` — `{query, agent_name?, k?}` → nearest memories (same locked embed pipeline)
- `GET /memory/{id}` — inspect full `alert_text` + `analysis`
- `PATCH /memory/{id}` — `{analysis}` edits analysis only (no re-embed); `{alert_text}` changes
  the identity and **re-embeds** with the same pipeline
- `DELETE /memory/{id}` — remove a noisy/bad entry

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
