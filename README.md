# RAM v2

SOC alert-triage pipeline: **Wazuh alert → AI agent analysis (Gemini + VirusTotal) →
deterministic triage → TheHive case**, with a semantic memory layer and a server-rendered
analyst console. Single company, single environment — no multi-tenancy.

Built in phases: (1) end-to-end pipeline, (1.5) TheHive/Wazuh hardening, (2) semantic
memory + operator API, (3) deterministic triage router, (4) read-only investigation agent,
(5) analyst console. **Phases 1–5 complete** (see Status at the bottom).

## Components
- **PostgreSQL + pgvector** — central datastore: semantic memory (RAG vectors),
  triage dedup state, and the analyst console (investigations, verdict reviews,
  triage feedback, users, audit log).
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
- **score < `TRIAGE_MEDIUM_THRESHOLD`** → auto-close. Default is no case (memory + log only);
  if `TRIAGE_LOW_CREATE_RESOLVED_CASE=true`, a case is created and **actually closed** in
  TheHive (status `Indeterminate`, stage `Closed`) — TheHive 5 has no literal `Closed` status,
  so closing sets a Closed-stage status and verifies the case reached that stage.
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

## Analyst console (`/console`)
A server-rendered console (Jinja2 + HTMX, **no SPA**) that exposes the agent's reasoning,
triage decisions, and memory store. It runs **inside the existing FastAPI service** (its own
`app/console/` module, kept separate from the webhook path) and sits **alongside TheHive** —
TheHive stays the case system of record; the console is a controller, not a case manager.

**Architecture & auth.** Per-analyst local accounts (`users` table, argon2 password hashes).
Session-based login via a signed cookie (`SESSION_SECRET_KEY`, Starlette `SessionMiddleware`).
Create the first account with `docker compose exec agent-service python -m app.console.create_user`
(interactive; no hardcoded credentials). The three auth planes are **fully independent**:
the analyst **session** (humans), the `/memory` **operator token** (M2M), and the **webhook**
(network-isolated on the compose network) — a session never grants token access and vice-versa.

**Audit.** Every consequential analyst action writes an `audit_log` row attributed to the
named analyst — **no action is anonymous**. Local DB actions write the action row and the
audit row in **one transaction** (atomic); memory edits are **audited first** (a failed audit
aborts the edit); TheHive actions are **verified against TheHive, then audited**.

**Views**
- **Triage queue** (`/console/`) — investigations with severity/label, attack type, host,
  source IP, rule, triage action, dedup occurrence, and a link to the TheHive case; filter by
  severity/action, search, paginate.
- **Investigation detail** (`/console/investigations/{id}`) — full agent verdict, complete
  tool-call trace, memory context, triage decision, and the layered analyst history.
- **Memory browser** (`/console/memory`) — list/semantic-search/inspect/edit/delete, reusing
  the locked embed pipeline (analysis-only edit does **not** re-embed; identity edit re-embeds).

**Action set** (all audited)
- Verdict **confirm / override** → `verdict_reviews`
- Triage **correct / incorrect** feedback → `triage_feedback`
- Memory **edit (analysis or identity) / delete**
- TheHive **close / set-severity / comment** — via the existing service account, scope limited
  to exactly these three; no tasks/observables/workflow.

**Write-once investigation record.** The webhook persists each alert's agent output to
`alert_investigations` (additive output-recording, after the pipeline, failure-isolated). The
row is **immutable** — a DB trigger rejects `UPDATE` (insert/delete only). The agent's analysis
and tool trace are ground truth; all human input (overrides, feedback) lives in the separate
`verdict_reviews` / `triage_feedback` tables, layered on top.

Console schema: `db/003_console.sql` (`users`, `audit_log`, `alert_investigations`,
`verdict_reviews`, `triage_feedback`).

## Ports
- TheHive UI/API `9000` (context path `/thehive`) · agent webhook `8000`
- Wazuh dashboard `8443` · Wazuh indexer `9200` · manager `1514/1515/55000`
- Postgres `127.0.0.1:5432`

## Status — Phases 1–5 COMPLETE
- [x] **Phase 1** — end-to-end pipeline: simulated alert → agent analysis → TheHive case
- [x] **Phase 1.5** — TheHive service account + admin rotation; Wazuh demo-password hardening
- [x] **Phase 2** — semantic memory (pgvector RAG) + token-protected `/memory` operator API
- [x] **Phase 3** — deterministic triage router with dedup/suppression
- [x] **Phase 4** — read-only investigation agent (bounded tool choice, least-privilege indexer user)
- [x] **Phase 5** — analyst console: session auth, full audit, triage queue / investigation
      detail / memory browser, analyst actions (verdict, feedback, memory, TheHive case control),
      write-once `alert_investigations` record
- [x] **Fix** — low-severity auto-close now actually closes the TheHive case (was a no-op:
      TheHive 5 rejects the literal `Closed` status)
