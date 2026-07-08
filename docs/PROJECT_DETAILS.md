# RAM v2 — Project Details

> Living reference for the RAM v2 SOC alert-triage system. Written against the
> source and the running stack as they exist on disk (not from memory). Where the
> code and the docs/README disagree, or where something is redundant, incomplete,
> or a security caveat, this file says so explicitly rather than papering over it.
>
> Last verified: 2026-07-02, against git branch `master` on the project VM.

---

## 1. Overview

**Goal.** RAM v2 automates the first pass of SOC alert triage. A Wazuh alert comes
in, an LLM agent investigates it using read-only enrichment tools, a deterministic
router decides what to do with it, and (when enabled) a TheHive case is created or
updated. A semantic memory layer gives the agent this company's own history of
prior alerts. A server-rendered analyst console lets a human review every decision.

**What it does, end to end.**
1. Receives a raw Wazuh alert on `POST /webhook/wazuh`.
2. Embeds the alert "identity" and retrieves prior related alerts for the same host (RAG).
3. Runs a bounded, read-only Gemini agent that investigates and emits a **structured** verdict (severity, attack type, MITRE, summary, recommended action).
4. Writes the alert + verdict back into semantic memory.
5. Runs a **deterministic** (no-LLM) triage router: auto-close / open case / flag-escalate, with time-windowed deduplication.
6. Persists a **write-once** investigation record for the console.
7. Surfaces everything to analysts in a session-authenticated console, where they can confirm/override verdicts, rate triage, browse/edit/delete memory, and drive a narrow set of TheHive case actions — all audited.

**Scope — single company, single environment.** There is no multi-tenancy anywhere:
one Postgres DB, one memory store keyed only by `agent_name` (host), one TheHive org,
one set of thresholds. This is a deliberate simplification, not an oversight.

**Investigation-only — no active response.** The agent's tools are strictly
read-only (VirusTotal reputation lookups, Wazuh Indexer queries, memory search).
The system **never** blocks an IP, isolates a host, kills a process, or disables an
account. The only outward writes it performs are: creating/commenting/closing
TheHive **cases**, and writing its own DB (memory, dedup, investigations, audit).

---

## 2. Architecture

### 2.1 Host / VM

| Property | Value |
|---|---|
| OS | Debian GNU/Linux 13 (trixie) |
| Kernel | Linux 6.12.94 (cloud amd64) |
| CPU | 4 cores |
| RAM | 15 GiB total |
| Disk | 99 GB root volume (~71 GB free) |
| Container engine | Docker 29.6.0, Docker Compose v2 |

Everything runs as Docker containers on this single VM, on one user-defined bridge
network. There is no orchestrator (no k8s/swarm) and no second host.

### 2.2 Docker services

Defined in `docker-compose.yml`. Image versions and port bindings below are the
**actually running** values (verified via `docker compose ps`), not just the file.

| Service (hostname) | Image | Host port → container | Purpose |
|---|---|---|---|
| `agent-service` | `ramv2/agent-service:0.1.0` (locally built) | `0.0.0.0:8000→8000` | FastAPI app: webhook, agent loop, triage, memory API, ops API, analyst console |
| `postgres` | `pgvector/pgvector:pg16` | `127.0.0.1:5432→5432` | Central datastore + pgvector (memory, dedup, console tables) |
| `thehive` | `strangebee/thehive:5.7.1` | `0.0.0.0:9000→9000` | Case management (system of record for cases) |
| `elasticsearch` | `elasticsearch:8.19.15` | internal only (`9200/9300` unpublished) | TheHive's index backend |
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.13.1` | `0.0.0.0:9200→9200` | Wazuh alert store (OpenSearch); queried read-only by agent tools |
| `wazuh.manager` | `wazuh/wazuh-manager:4.13.1` | `1514,1515,55000/tcp`, `514/udp` | Wazuh alert engine; posts alerts to the webhook via a custom integration |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.13.1` | `0.0.0.0:8443→5601` | Wazuh UI |

> **Version note:** the compose image tag is `ramv2/agent-service:0.1.0`, but the
> FastAPI app declares `version="0.2.0"` in `main.py`. Cosmetic mismatch only — the
> tag is a fixed local build label; it does not track the app version.

### 2.3 How they connect

- **Network:** all services share the compose bridge network `ramnet` (external
  name `ramv2-net`) and address each other by hostname (`postgres`, `thehive`,
  `wazuh.indexer`, `agent-service`, …).
- **Wazuh manager → agent-service:** the manager runs a custom integration
  (`wazuh/integrations/custom-ramv2.py`, mounted into the manager) that POSTs alert
  JSON to `http://agent-service:8000/webhook/wazuh` over `ramnet`.
- **agent-service → Postgres:** psycopg3 connection pool (`app/db.py`) using the
  `postgres_dsn` built from env.
- **agent-service → Wazuh Indexer:** HTTPS to `https://wazuh.indexer:9200` as the
  least-privilege `ram_agent_ro` user, verifying TLS against `/certs/root-ca.pem`
  (the only file bind-mounted into the agent container).
- **agent-service → TheHive:** HTTPS/HTTP to TheHive's `/api/v1` using the service
  account bearer token.
- **agent-service → Gemini / VirusTotal:** outbound HTTPS to the public APIs.
- **TheHive → Elasticsearch:** internal index traffic on `ramnet`.

> **Isolation caveat (read this):** the agent container publishes port **8000 on
> `0.0.0.0`**, and that single port serves *all* routes — `/webhook/wazuh`,
> `/health`, `/console`, `/memory`, `/ops`. The webhook itself has **no
> authentication**; it relies on nothing but network placement. So "the webhook is
> network-isolated" is only true if a **host/cloud firewall** restricts inbound
> 8000. At the compose level it is reachable by anything that can reach the VM's
> port 8000. See §7 and §9.

---

## 3. Codebase

All application code lives in `agent-service/app/`. Runtime: Python 3.12-slim,
FastAPI + Uvicorn, run as non-root user `appuser` (uid 10001). Dependencies
(`requirements.txt`): fastapi, uvicorn, pydantic/pydantic-settings, google-genai,
httpx, psycopg[binary,pool], jinja2, python-multipart, argon2-cffi, itsdangerous.

> **Deployment note:** the app directory is **baked into the image** (`COPY app`),
> not bind-mounted. Only `/certs/root-ca.pem` is mounted. **Any code change
> therefore requires `docker compose build agent-service && docker compose up -d
> agent-service`** to take effect — editing files on disk alone does nothing to the
> running container.

### 3.1 Entry point & wiring

- **`main.py`** — builds the FastAPI app, wires routers and middleware.
  - Includes `memory_router` (`/memory`), `ops_router` (`/ops`), `console_router` (`/console` + auth).
  - Adds Starlette `SessionMiddleware` (signed cookie; `same_site=lax`; `https_only` from config) for the console.
  - Mounts static assets at `/console/static`.
  - Registers the `NeedsLogin → needs_login_handler` exception handler (redirect to login).
  - `GET /health` → `{status, gemini_model, thehive_enabled, metrics}` (metrics from the in-process counters).
  - `POST /webhook/wazuh` → parses JSON, calls `webhook.process_alert`, maps `AgentError→502` and any other exception→500.

- **`config.py`** — `Settings` (pydantic-settings, env-driven). Single source for
  model names, thresholds, timeouts, DSN, tokens. `get_settings()` is `lru_cache`d.
  Notable derived props: `postgres_dsn`, `thehive_enabled` (true iff an API key is set).

- **`logging_conf.py`** — plain stdout logging; deliberately quiets httpx; never logs secrets/bodies.

- **`db.py`** — lazy psycopg3 `ConnectionPool` (`get_pool()`), and `vector_literal()`
  which formats a float list as a pgvector text literal at full precision (vectors
  are passed as text with an explicit `::vector` cast — no binary vector adapter).

### 3.2 The ingestion pipeline

- **`webhook.py`** — orchestrates one alert. Key functions:
  - `normalize_alert(payload)` — unwraps common Wazuh envelopes (`alert`/`_source`/`data`) and validates into `WazuhAlert`.
  - `_retrieve_memory(alert)` — embeds the identity **once**, retrieves prior host memories; **degrades gracefully** (embedding/DB failure → proceeds with empty context, logged not swallowed). Returns `(embedding, memories, context_text)`.
  - `process_alert(payload)` — the full sequence (see §4). Contains the failure-isolated console-record block that emits the greppable `CONSOLE_RECORD_FAILURE alert_id=…` marker and bumps the `console_record_failures` counter.

  > **Minor redundancy (not a bug):** `process_alert` computes
  > `identity = memory.identity_string(alert)` at line ~62, and `_retrieve_memory`
  > independently computes the identity again to embed it. The identity string is
  > cheap and deterministic, so this double call is harmless, just slightly
  > redundant. The **embedding** itself is computed only once and reused for write-back.

- **`agent.py`** — the read-only investigation agent (Phase 4). **Bounded tool
  choice:** the model may freely pick tools, but only from the registry allowlist,
  and it cannot act.
  - `run_agent(alert, memory_context)` → `(AnalysisResult, evidence, tool_trace)`.
  - Loop capped at `agent_max_iterations` (Gemini `tool_config` mode `ANY`, `allowed_function_names` = registry tools + `submit_analysis`).
  - Ends when the model calls `submit_analysis`; if the cap is hit first, it forces a final submit (config restricted to only `submit_analysis`); if that still fails, `_fallback_analysis()` derives a verdict from `rule_level` so **an alert is never dropped**.
  - `_build_prompt()` includes rule metadata, extracted public IPs, source user, and the retrieved memory context. Every tool call is logged (`AGENT tool_call …`) and appended to `tool_trace`.

- **`triage.py`** — deterministic router (Phase 3), **no LLM**.
  - `route_and_execute(alert, analysis, enrichment)` → `(TriageDecision, case_or_None)`.
  - `_branch(score)` by env thresholds: `< MEDIUM` = low; `MEDIUM..HIGH` = medium; `>= HIGH` = high.
  - **low** → `auto_close` (default: memory + log only, no case; if `TRIAGE_LOW_CREATE_RESOLVED_CASE=true` and TheHive enabled, creates then closes a case).
  - **medium/high** → create case (`create_open` / `create_flagged`), subject to dedup.
  - `_norm_source_ip()` — normalizes/blanks junk IPs (`0.0.0.0`, `::`, `-`, etc.). **No source_ip → never deduped** (always create, to avoid false suppression).
  - `_dedup_and_execute()` — dedup key `agent_name|rule_id|source_ip`, `SELECT … FOR UPDATE` on `triage_dedup`; within the window a repeat **suppresses** the new case and increments `occurrence_count` (and comments on the existing case); otherwise creates and (re)sets the dedup row via `ON CONFLICT … DO UPDATE`.
  - Every decision logged as `TRIAGE decision …`.

- **`thehive.py`** — minimal TheHive 5 client.
  - Pipeline-side: `create_case`, `add_comment`, `close_case` (best-effort auto-close).
  - Console-side (analyst-driven, strict, verify-then-audit): `get_case`, `get_case_comments`, `set_severity`, `post_comment`, `close_case_strict`.
  - **Closing logic (locked behavior):** TheHive 5 has **no literal `Closed` status**. Closing sets a status whose *stage* is Closed. `CLOSED_STATUSES = (Indeterminate, TruePositive, FalsePositive, Duplicated, Other)`, default `Indeterminate`; callers then read the case back and confirm `stage == "Closed"`.
  - Scope is deliberately limited to **close / set-severity / comment** (+ read-backs). No tasks, observables, or workflow operations are exposed.

### 3.3 Agent tools (`app/tools/`)

Importing the `tools` package registers every tool into `TOOL_REGISTRY` via import
side effects. All tools are **read-only** and size-capped.

- **`registry.py`** — `Tool`/`ToolContext` dataclasses; `register`, `build_declarations`, `allowed_names`, and `dispatch`. `dispatch()` strips the bookkeeping `reason` arg, **never lets a tool exception reach the loop** (returns `{"error": …}`), and `cap_result()` trims oversized results (drops list items before falling back to a truncated preview) using `tool_max_result_chars`.
- **`submit.py`** — declares the terminal `submit_analysis` function (the LOCKED output shape). It has **no handler**; the loop treats this name specially to end the investigation.
- **`netutil.py`** — `is_public_ip()` (skips private/loopback/link-local/reserved/etc.) and `extract_public_ips()`. Private-IP skipping is a locked rule carried from RAM v1.
- **`virustotal.py`** — `virustotal_ip_lookup`, `lookup_file_hash`, `lookup_domain` (VT API v3 reputation; validates hash/domain formats; skips private IPs).
- **`wazuh_indexer.py`** — `get_related_logs`, `get_host_alert_history`, `get_user_activity`, `get_full_log_context`. All query `wazuh-alerts-*` as `ram_agent_ro`, shape/cap results, and surface cross-host activity for user queries (lateral-movement signal).
- **`memory_tool.py`** — `search_memory`: exposes semantic memory search to the agent (same locked embed pipeline).

### 3.4 Semantic memory (`memory.py`)

The RAG layer. **This is the locked pipeline** (see §6).
- `embed(text)` — the single locked entry point: `gemini-embedding-001`, `output_dimensionality=768`, `task_type=SEMANTIC_SIMILARITY`, then **client-side L2 normalization** (`_l2_normalize`). Applied symmetrically at insert and query.
- `identity_string(alert)` — the locked identity format: `Rule: <desc> | SrcIP: <ip> | Groups: <groups> | Log: <full_log>`.
- `retrieve(agent_name, query_vec)` — hybrid: top-K most similar (`<=>` cosine) + last-N most recent, deduped by id, scoped to the host.
- `write_back(alert, identity, analysis, embedding)` — inserts a memory row **reusing the already-computed embedding** (no double embed).
- Operator CRUD reused by both the token API and the console: `list_memories`, `get_memory`, `search_memories`, `update_analysis` (**no re-embed**), `reembed_identity` (**re-embeds** via `embed()`), `delete_memory`.
- `parse_alert_timestamp` / `format_memories_for_prompt` are helpers.

### 3.5 APIs (operator + ops)

- **`memory_api.py`** — the `/memory` operator router. `require_operator()` is a
  **constant-time** (`hmac.compare_digest`) bearer-token check guarding the whole
  router; **fails closed** (503) if no token is configured. Endpoints:
  `GET /memory`, `POST /memory/search`, `GET /memory/{id}`, `PATCH /memory/{id}`
  (analysis-only vs identity-change → re-embed), `DELETE /memory/{id}`. Responses
  never include the raw embedding.
- **`ops_api.py`** — the `/ops` router, guarded by the **same** `require_operator`
  token (M2M only, not reachable from a browser session). `GET /ops/reconciliation?window_hours=…`
  returns memory-row vs investigation-row counts and their divergence.
- **`metrics.py`** — tiny thread-safe in-process counter holder (`console_record_failures`).
  Explicitly **not** a system of record: resets on restart; the DB + audit log are
  the source of truth. Surfaced on `/health`; reconcile via `/ops/reconciliation`.

### 3.6 Analyst console (`app/console/`)

Server-rendered Jinja2 + HTMX, **no SPA**. Runs inside the same FastAPI app but in
its own module, kept separate from the webhook path.
- **`auth.py`** — argon2 password hashing; signed-cookie sessions. `current_analyst`/`require_analyst` (raises `NeedsLogin`); `/console/login`, `/console/logout` (both audited). Failed logins are logged and return 401.
- **`store.py`** — all console DB access:
  - `get_user`/`create_user`.
  - `record_investigation` — the **write-once** insert of agent output.
  - `list_investigations` / `get_investigation` (queue + detail, joins verdict reviews + triage feedback).
  - `reconcile_counts(window_hours)` — the memory-vs-investigation count check.
  - Audit spine: `write_audit` (own transaction, **re-raises on failure** — auditing is mandatory) and `_audit_on` (same-transaction variant).
  - `add_verdict_review` / `add_triage_feedback` — action **and** audit row in **one transaction** (atomic).
- **`router.py`** — all console routes (session-authenticated via `require_analyst`):
  - `GET /console/` — triage queue (filter by severity/action, search, paginate).
  - `GET /console/investigations/{id}` — investigation detail. Resolves each write-once `retrieved_id` to its current memory via `_resolve_retrieved()`; a since-deleted id renders as "deleted / not found" and is **never** a 404 (dangling refs are expected after memory cleanup).
  - Analyst actions: `POST …/verdict` (confirm/override), `POST …/feedback` (correct/incorrect).
  - TheHive actions: `POST …/case/close|severity|comment` — each logs a pre-call `THEHIVE_INTENT …` marker, performs the change, **verifies via read-back**, then writes the audit row.
  - **Memory browser:** `GET /console/memory` (filter by agent/source_ip/rule_id + semantic search box + pagination), `GET /console/memory/{id}` (inspect), `POST …/analysis` (edit analysis, **no re-embed**, audited first), `POST …/identity` (edit identity, **re-embeds**, audited first), `POST …/delete` (audited first).
- **`create_user.py`** — interactive CLI (`python -m app.console.create_user`), run
  inside the container. Reads the password with `getpass` (never echoed/logged/CLI-passed),
  stores only the argon2 hash, and writes a `user_create` audit row.
- **`templating.py`** — shared Jinja2 `templates` instance. Templates live in
  `console/templates/` (`base`, `login`, `index`, `queue`, `investigation`,
  `memory_list`, `memory_detail`, `not_found`); assets in `console/static/`
  (`style.css`, `htmx.min.js`).

### 3.7 Schemas (`schemas.py`)

- `WazuhAlert` / `WazuhRule` / `WazuhAgent` — lenient inbound models (`extra="allow"`; only modeled fields are relied on). `rule_level` / `description` convenience props.
- `AnalysisResult` — **the LOCKED agent output**: `severity_score` (0–100), `severity_label` (`info|low|medium|high|critical`), `attack_type`, `mitre[]`, `summary`, `recommended_action`. `MitreMapping` requires `technique_id`.
- `TriageDecision` — branch/action/reason + dedup fields.
- `WebhookResponse` — the `POST /webhook/wazuh` response envelope.
- `MemorySearchRequest` / `MemoryUpdateRequest` (the latter `extra="forbid"`).

---

## 4. End-to-end request flow

`POST /webhook/wazuh` → `main.wazuh_webhook` → `webhook.process_alert(payload)`:

1. **Normalize** — `normalize_alert(payload)` → `WazuhAlert`.
2. **Identity + retrieve** — `memory.identity_string(alert)`, then
   `_retrieve_memory(alert)` → `memory.embed(identity)` (once) and
   `memory.retrieve(agent_name, embedding)` → `(embedding, memories, memory_context)`.
   (Degrades to empty context on failure.)
3. **Investigate** — `run_agent(alert, memory_context)`:
   loop of `client.models.generate_content(...)` → `_first_function_call` →
   `tools.dispatch(name, args, ctx)` for each read-only tool, until
   `submit_analysis` → `AnalysisResult` (or forced submit / `_fallback_analysis`).
   Returns `(analysis, enrichment, tool_trace)`.
4. **Write back to memory** — `memory.write_back(alert, identity, analysis, embedding)`
   (reuses the step-2 embedding; failure logged, analysis preserved).
5. **Triage** — `triage.route_and_execute(alert, analysis, enrichment)` →
   `_branch` → low `auto_close` **or** `_create` / `_dedup_and_execute` (with
   `thehive.create_case` / `add_comment`). Returns `(decision, case)`. Failure here
   is caught so memory/analysis aren't lost.
6. **Record (write-once)** — `console_store.record_investigation(...)` persists the
   agent output + trace + `retrieved_ids` + triage decision + case linkage. Fully
   failure-isolated: on error it bumps `metrics.increment("console_record_failures")`
   and logs `CONSOLE_RECORD_FAILURE alert_id=…` — **never** breaks ingestion.
7. **Respond** — returns `WebhookResponse` (analysis, case, triage, tool_trace,
   memory summary) as HTTP 200.

**Later, asynchronously, a human** logs into `/console/`, opens an investigation,
reviews the verdict/trace/memory context, and optionally confirms/overrides the
verdict, rates the triage, edits/deletes memory, or closes/comments/re-severities
the TheHive case — every such action writing an attributed `audit_log` row.

---

## 5. Database

PostgreSQL 16 + pgvector (`pgvector/pgvector:pg16`), database `ramv2`, role `ramv2`.
Schema is applied by the ordered SQL files in `db/`. Current row counts (live) are
small — this is a validation/test dataset, not production volume.

### `soc_memory_vectors` — semantic memory (`db/001_memory.sql`)
| Column | Type | Purpose |
|---|---|---|
| `id` | bigint identity PK | memory row id (referenced by `alert_investigations.retrieved_ids`, **no FK**) |
| `agent_name` | text NOT NULL | host; the retrieval scope key |
| `source_ip` | text | source IP (filter) |
| `rule_id` | text | Wazuh rule id (filter) |
| `alert_text` | text NOT NULL | the **embedded identity string** — byte-identical to what was embedded |
| `analysis` | jsonb NOT NULL | the agent's `AnalysisResult` |
| `embedding` | vector(768) NOT NULL | L2-normalized embedding |
| `alert_timestamp` | timestamptz | event time (nullable) |
| `created_at` | timestamptz | store time |

Indexes: HNSW `vector_cosine_ops` on `embedding` (unit vectors ⇒ cosine == dot),
plus btree on `agent_name`, `source_ip`, `rule_id`, `created_at`.

### `triage_dedup` — dedup / suppression state (`db/002_triage_dedup.sql`)
| Column | Type | Purpose |
|---|---|---|
| `dedup_key` | text PK | `agent_name\|rule_id\|source_ip` |
| `agent_name`,`rule_id`,`source_ip` | text | components (for inspection) |
| `case_id`,`case_number` | text / bigint | the case this key maps to |
| `occurrence_count` | int NOT NULL default 1 | dupes seen in the current window |
| `first_seen`,`last_seen` | timestamptz | window bookkeeping |

One active record per key; no-source_ip alerts are never written here.

### `users` — analyst accounts (`db/003_console.sql`)
`id`, `username` (unique), `password_hash` (argon2), `display_name`, `role`
(default `analyst`; CLI also allows `admin`), `disabled`, `created_at`.

### `audit_log` — attributed action log (`db/003_console.sql`)
`id`, `actor_username` NOT NULL, `action` NOT NULL, `target_type`, `target_id`,
`before` jsonb, `after` jsonb, `detail`, `created_at`. Indexed on `created_at` and
`actor_username`. **Every consequential action writes a row here** (see §7).

### `alert_investigations` — WRITE-ONCE agent output (`db/003_console.sql`)
Columns: `id`, `alert_id`, `agent_name`, `source_ip`, `rule_id`, `severity_score`,
`severity_label`, `attack_type`, `analysis` jsonb, `tool_trace` jsonb, `memory_context`,
`retrieved_ids` jsonb, `triage_action`, `triage_branch`, `occurrence_count`,
`suppressed`, `case_id`, `case_number`, `created_at`.

> **Write-once trigger.** `reject_update_alert_investigations()` +
> `alert_investigations_no_update` (`BEFORE UPDATE … FOR EACH ROW`) raises
> `alert_investigations is write-once: agent output is immutable`. INSERT and DELETE
> are allowed (delete is for retention/cleanup); UPDATE is rejected at the DB. This
> is why `retrieved_ids` can go stale — the snapshot can't be rewritten when a
> referenced memory row is later deleted (handled gracefully in the console UI).

### `verdict_reviews` — human verdict layer (`db/003_console.sql`)
`id`, `investigation_id` **FK → alert_investigations(id)**, `actor_username`,
`action` CHECK in (`confirm`,`override`), `override_payload` jsonb, `reason`, `created_at`.

### `triage_feedback` — human triage rating (`db/003_console.sql`)
`id`, `investigation_id` **FK → alert_investigations(id)**, `actor_username`,
`rating` CHECK in (`correct`,`incorrect`), `reason`, `created_at`. Stored for tuning;
**no behavior change** from it yet (see §9).

---

## 6. Locked invariants

These are contracts the code depends on. Each is enforced/asserted in a specific place.

1. **Embedding pipeline is byte-identical** — `gemini-embedding-001`, 768 dims,
   `SEMANTIC_SIMILARITY`, client-side L2 normalization, symmetric at insert & query.
   - Enforced by the single entry point `memory.embed()` (`memory.py`, `_l2_normalize` unconditional; dim check raises on mismatch). Config in `config.py` (`embedding_model/dim/task_type`, commented LOCKED). Schema pins `vector(768)` (`db/001_memory.sql`). Every write/re-embed path (`write_back`, `reembed_identity`, `search_memories`) routes through `embed()`.

2. **Identity string format is fixed** — `Rule: <desc> | SrcIP: <ip> | Groups: <groups> | Log: <full_log>`.
   - Enforced by `memory.identity_string()`; stored verbatim in `alert_text`.

3. **Analysis output shape is locked** — `AnalysisResult` (severity_score/label,
   attack_type, mitre, summary, recommended_action).
   - Enforced by `schemas.AnalysisResult` + the `submit_analysis` declaration in `tools/submit.py`. The triage router reads only these fields, so the shape must not drift.

4. **Agent is read-only with bounded tool choice** — the model may only call
   allowlisted tools and cannot act.
   - Enforced by `agent._config()` (`function_calling_config` mode `ANY`, `allowed_function_names` = registry + `submit_analysis`), the registry allowlist, `dispatch()`'s unknown-tool guard, the iteration cap, forced submit, and `_fallback_analysis` (alert never dropped).

5. **`alert_investigations` is write-once** — agent output is immutable.
   - Enforced by the DB trigger `alert_investigations_no_update` (`db/003_console.sql`). Verified live (an `UPDATE` is rejected).

6. **Auditing is mandatory for consequential actions** — no consequential action is anonymous or unaudited.
   - Enforced by `store.write_audit` (re-raises on failure) and the same-transaction `_audit_on`. Memory edits/deletes audit **first** (a failed audit aborts the mutation); DB actions write action+audit atomically; TheHive actions verify-then-audit.

7. **TheHive has no literal `Closed` status** — close by setting a Closed-*stage* status and verifying.
   - Enforced by `thehive.CLOSED_STATUSES` / `close_case_strict` + the stage read-back in `close_case` and the console close route.

8. **No source_ip ⇒ never deduped** (always create; avoids false suppression).
   - Enforced in `triage.route_and_execute` / `_norm_source_ip`.

9. **Private/reserved IPs are never sent to VirusTotal.**
   - Enforced by `netutil.is_public_ip` (used in `virustotal._ip_lookup` and IP extraction).

---

## 7. Security

**Three independent auth planes** (a credential for one never grants another):
1. **Analyst session** (humans) — argon2-hashed local accounts (`users`), signed-cookie
   sessions via Starlette `SessionMiddleware` (`SESSION_SECRET_KEY`). Guards all
   `/console/*` routes (`require_analyst`). Human actions always run under the named
   analyst identity — never the operator token.
2. **Operator bearer token** (machine-to-machine) — `OPERATOR_API_TOKEN`, constant-time
   checked by `require_operator`; guards `/memory` **and** `/ops`. Fails closed if unset.
   Not reachable from a browser session.
3. **Webhook** — `/webhook/wazuh`, **no application auth**; intended to be reachable
   only from the Wazuh manager over `ramnet`. **Caveat:** as configured, port 8000 is
   published on `0.0.0.0`, so true isolation depends on a host/cloud firewall (see §2.3, §9).

**Least-privilege service identities.**
- `ram_agent_ro` — a read-only OpenSearch/Wazuh-indexer user (created by
  `scripts/bootstrap-indexer-rouser.sh`); write/security calls are rejected. The
  agent's indexer tools use only this account.
- TheHive **service account** — a scoped org account (minted by
  `scripts/bootstrap-thehive.sh`); the console exposes only close/severity/comment.
- The agent container runs as **non-root** (`appuser`, uid 10001).

**Audit log** — `audit_log` records every consequential action, attributed to a named
actor: logins/logouts, verdict confirm/override, triage feedback, memory
edit/re-embed/delete, TheHive close/severity/comment, and CLI user creation. Auditing
is a hard requirement (`write_audit` re-raises on failure). Additionally, TheHive
actions emit a pre-call `THEHIVE_INTENT …` log line so an intent trace survives even
if the post-verification audit write were to fail (this narrows, but does not fully
eliminate, the audit-gap noted in §9).

**Secret handling** — all secrets come from the gitignored `.env`; none are hardcoded.
Logging config avoids secret values and request bodies. Operator API responses never
include raw embeddings.

---

## 8. Configuration (env variables — names only)

Loaded from `.env` (gitignored). `config.py` supplies defaults for anything not set.
Names present in the running `.env` and/or read by `config.py`:

**AI / external APIs**
- `GEMINI_API_KEY` — Gemini API key (analysis + embeddings).
- `GEMINI_MODEL` — analysis model (currently `gemini-2.5-flash`).
- `VIRUSTOTAL_API_KEY` — VirusTotal API v3 key.

**TheHive**
- `THEHIVE_URL` — base URL of TheHive (the client appends `/api/v1`). *Note:* the
  `config.py` default is `http://thehive:9000`, but the `.env`/README value includes
  the `/thehive` context path; the env value is what's used at runtime.
- `THEHIVE_API_KEY` — service-account bearer token (enables case creation).
- `THEHIVE_ORGANISATION` — org name (`ram-v2`).
- `THEHIVE_ADMIN_USER`, `THEHIVE_ADMIN_PASSWORD` — admin account (rotated by bootstrap).
- `THEHIVE_SECRET` — TheHive application secret (used by rendered config).

**PostgreSQL**
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` — DB connection (DSN built in config).

**Agent service**
- `AGENT_LOG_LEVEL` — log level.
- `AGENT_MAX_ITERATIONS` — agent loop cap.

**Wazuh indexer (read-only tools)**
- `WAZUH_INDEXER_RO_USER`, `WAZUH_INDEXER_RO_PASSWORD` — least-privilege indexer user.
- (`WAZUH_INDEXER_URL`, `WAZUH_INDEXER_CA_CERT`, timeouts have config defaults and are not set in `.env`.)

**Operator / console**
- `OPERATOR_API_TOKEN` — bearer token for `/memory` and `/ops` (M2M).
- `SESSION_SECRET_KEY` — signs console session cookies.
- `CONSOLE_THEHIVE_PUBLIC_URL` — base URL for case deep-links from the console.
- (`SESSION_MAX_AGE_HOURS`, `CONSOLE_COOKIE_SECURE` have config defaults; set the
  latter true behind TLS.)

**Triage router**
- `TRIAGE_MEDIUM_THRESHOLD`, `TRIAGE_HIGH_THRESHOLD` — severity_score branch cutoffs.
- `TRIAGE_DEDUP_WINDOW_HOURS` — dedup window.
- `TRIAGE_LOW_CREATE_RESOLVED_CASE` — whether low-severity also creates+closes a case.

**Infra / other services (consumed by compose, not the app)**
- `ELASTICSEARCH_PASSWORD` — TheHive's Elasticsearch backend.
- `WAZUH_INDEXER_PASSWORD`, `WAZUH_API_PASSWORD`, `WAZUH_DASHBOARD_PASSWORD` — Wazuh stack.
- `UID`, `GID` — container user mapping for elasticsearch/thehive.

> Names only — never commit or print values. `.env.example` is the empty-valued template.

---

## 9. Current state

**Phases 1–5 + Tier 1 are complete and verified against the running stack.**

| Phase | Scope | State |
|---|---|---|
| 1 | End-to-end pipeline (alert → agent → TheHive case) | ✅ complete |
| 1.5 | TheHive service account + admin rotation; Wazuh demo-password hardening | ✅ complete |
| 2 | Semantic memory (pgvector RAG) + token-protected `/memory` operator API | ✅ complete |
| 3 | Deterministic triage router (dedup/suppression) | ✅ complete |
| 4 | Read-only investigation agent (bounded tool choice, least-privilege indexer user) | ✅ complete |
| 5 | Analyst console (session auth, full audit, queue / investigation detail / memory browser, analyst + TheHive actions, write-once record) | ✅ complete |
| Tier 1 | Visibility/cleanup: `CONSOLE_RECORD_FAILURE` marker + `/health` counter + `/ops/reconciliation`; stale README/model fixes; TheHive pre-call intent log; dead-import removal | ✅ complete & verified |

**What works end-to-end right now** (live-verified): the stack is up and healthy
(`/health` → `gemini-2.5-flash`, `thehive_enabled: true`, `console_record_failures: 0`);
alerts flow through embed → retrieve → agent → memory write-back → triage → write-once
record; the console authenticates, lists/opens investigations, browses/searches/edits/
deletes memory, records verdict/feedback, and drives the three TheHive case actions,
all audited; `/ops/reconciliation` reports memory vs investigation balance
(currently `divergence: 0`); and the console renders since-deleted retrieved memory
ids as "deleted / not found" rather than erroring. There is currently one analyst
account (`testanalyst`), and the dataset is small (6 memory rows / 6 investigations),
i.e. validation-scale, not production traffic.

### Known limitations / open items

- **Triage & severity calibration pending.** Thresholds (`40`/`80`), the dedup window
  (`6h`), and the agent's severity scoring have **not** been calibrated against a
  labeled real-alert corpus. `triage_feedback` is **collected but not yet used** to
  change any behavior — it's a dataset for future tuning.
- **TheHive audit-gap (narrowed, not closed).** Console TheHive actions are
  perform → verify → audit, with a pre-call `THEHIVE_INTENT` log. A small window still
  exists where a verified TheHive change could land while the subsequent audit-row
  write fails; the intent log records that an attempt was made, but the authoritative
  audit row would be missing. This is a deliberate, documented trade-off (the
  alternative — a distributed transaction across TheHive and Postgres — was out of scope).
- **Webhook exposure.** `/webhook/wazuh` has no application auth and port 8000 is
  published on `0.0.0.0`. Safe only if a host/cloud firewall restricts inbound 8000 to
  the manager. This should be tightened (bind to an internal interface / firewall /
  add a shared secret) before any exposed deployment.
- **Deferred production-hardening.** Rotate the remaining Wazuh demo users
  (kibanaro, logstash, readall, snapshotrestore); set `CONSOLE_COOKIE_SECURE=true`
  behind TLS; no HTTPS terminator/reverse proxy in front of the console/webhook yet;
  no automated DB backups/retention policy for the write-once and memory tables;
  in-process metrics are non-durable (reset on restart) by design.
- **Minor code cleanliness.** Redundant identity computation in `process_alert`
  (§3.2); image tag (`0.1.0`) vs app version (`0.2.0`) mismatch (§2.2). Neither
  affects behavior.
- **`retrieved_ids` has no FK** to `soc_memory_vectors` by design (write-once
  snapshot), so references can dangle after memory deletion. The console handles this;
  any *new* consumer of `retrieved_ids` must tolerate missing ids.

---

*Generated from source and the running system. If you change the pipeline, the
locked invariants (§6), or the service topology (§2), update this file in the same change.*
