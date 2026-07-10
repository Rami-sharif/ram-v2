# RAM v2 — Project Status and Reference Guide

This document is the canonical project-status reference for RAM v2. It is written to be useful to both human operators and LLM-based assistants that need to understand the repository, the runtime architecture, the business logic, and the operational constraints.

This guide is intentionally explicit about what is implemented, how it is wired, what is intentionally restricted, and what should be treated as a caveat rather than assumed behavior.

## 1. Purpose of the project

RAM v2 is a SOC alert-triage pipeline that takes alerts from Wazuh, runs an AI investigation loop, stores the result in semantic memory, applies deterministic triage logic, and optionally creates or updates cases in TheHive.

The system is designed around a single-company, single-environment deployment model. There is no multi-tenancy, no tenant isolation layer, and no generic plugin ecosystem. The implementation is a focused prototype/operational tool for one SOC environment.

### Core goals
- Ingest Wazuh alerts and transform them into structured investigation output.
- Use an LLM agent for investigation, but keep the agent read-only and bounded.
- Store prior alert context in a semantic memory layer for future investigations.
- Apply deterministic routing logic instead of relying on the model for final action selection.
- Surface results to analysts through a server-rendered console with audit logging.
- Preserve a durable record of investigations and analyst actions.

### Project scope
- Alert ingestion from Wazuh.
- AI-driven enrichment using Gemini and read-only tools.
- Semantic memory using pgvector.
- Deterministic triage routing and deduplication.
- Human review interface with audit history.
- TheHive case integration for escalation and case management.

## 2. Current implementation status

As of the current repository state, the project is functionally complete for the intended phases:

- Phase 1: end-to-end pipeline from simulated alert to investigation and case creation.
- Phase 1.5: TheHive service-account integration and security hardening around default credentials.
- Phase 2: semantic memory with pgvector-backed retrieval and operator API.
- Phase 3: deterministic triage router with deduplication logic.
- Phase 4: read-only investigation agent with bounded tool use and least-privilege indexer access.
- Phase 5: analyst console with session authentication, audit logging, investigation views, memory management, and case actions.

### Important status note
The implementation is not a generic AI security platform. It is a concrete, opinionated SOC workflow system with strict guardrails and a narrow feature set.

## 3. Repository layout

The repository is organized around a Docker-based multi-service deployment.

### Top-level structure
- [docker-compose.yml](../docker-compose.yml): full stack definition for all services.
- [README.md](../README.md): short high-level project overview and setup guidance.
- [docs/PROJECT_DETAILS.md](PROJECT_DETAILS.md): deeper implementation notes.
- [docs/PROJECT_STATUS.md](PROJECT_STATUS.md): this document.
- [agent-service/](../agent-service): FastAPI application service.
- [db/](../db): SQL schema files for Postgres.
- [samples/](../samples): example Wazuh alerts.
- [scripts/](../scripts): setup, bootstrap, and rendering scripts.
- [wazuh/](../wazuh): Wazuh-related configs, integrations, and cert assets.
- [thehive/](../thehive): TheHive configuration, data, and logs.
- [elasticsearch/](../elasticsearch): local Elasticsearch data and logs.

### Service directories
- [agent-service/app](../agent-service/app): application code for the FastAPI service.
- [agent-service/app/console](../agent-service/app/console): analyst console, auth, templates, static assets.
- [agent-service/app/tools](../agent-service/app/tools): read-only investigation tools.

## 4. Runtime architecture

The stack is composed of several containers linked over a Docker bridge network.

### Core services
- Agent service: FastAPI application that receives alerts, runs the investigation loop, handles memory APIs, exposes the analyst console, and interacts with TheHive.
- PostgreSQL with pgvector: central datastore for semantic memory, investigation state, deduplication state, console records, and audit trails.
- TheHive: case management system of record for triage outcomes.
- Elasticsearch: TheHive’s backing index service.
- Wazuh manager: alert generation and webhook integration point.
- Wazuh indexer: alert store used by the agent for read-only enrichment.
- Wazuh dashboard: UI for Wazuh.

### Network and deployment model
The services run on a single host and communicate over the compose network. There is no Kubernetes, no distributed orchestration, and no multi-tenant architecture.

### Runtime assumptions
- The deployment is intended to run on a single VM or host.
- Configuration comes from environment variables and local files, not from a separate config service.
- The application container is built from the local repository.

## 5. Key components and responsibilities

### 5.1 FastAPI agent service
The main application runs in [agent-service/app/main.py](../agent-service/app/main.py).

Responsibilities:
- expose health and root endpoints.
- accept webhook events at /webhook/wazuh.
- mount the console routes.
- expose the memory and ops API.
- wire session middleware for analyst console authentication.

### 5.2 Configuration
Configuration is centralized in [agent-service/app/config.py](../agent-service/app/config.py).

Key configuration domains:
- Gemini model and API settings.
- VirusTotal settings and caps.
- TheHive connection settings.
- Wazuh indexer connection settings.
- Postgres DSN and memory parameters.
- Triage thresholds and dedup window.
- Operator API token.
- Console session settings.

### 5.3 Alert ingestion and orchestration
The alert pipeline is orchestrated in [agent-service/app/webhook.py](../agent-service/app/webhook.py).

It performs the following high-level tasks:
1. Normalize incoming alert payloads.
2. Build the identity string for the alert.
3. Retrieve semantic memories relevant to the alert.
4. Run the investigation agent.
5. Write results back to memory.
6. Run the deterministic triage router.
7. Persist the write-once investigation record for the console.

### 5.4 Investigation agent
The investigation loop lives in [agent-service/app/agent.py](../agent-service/app/agent.py).

Important characteristics:
- The agent is bounded.
- The model may choose tools from an allowlist, but it cannot perform destructive actions.
- Tool use is logged and surfaced in the investigation detail view.
- The loop terminates on a submit action or after a maximum iteration cap.
- A fallback analysis is used if the loop fails to produce a clean final result, so alerts are not dropped.

### 5.5 Deterministic triage router
The triage logic lives in [agent-service/app/triage.py](../agent-service/app/triage.py).

This part does not use the LLM. It makes the final action decision based on severity score and deduplication state.

Routing branches:
- Low severity: usually auto-close.
- Medium severity: create an open case for review.
- High severity: create a flagged case.

Deduplication uses a composite key and a time window. Alerts without a usable source IP are never deduped to avoid false suppression.

### 5.6 TheHive integration
TheHive client behavior is implemented in [agent-service/app/thehive.py](../agent-service/app/thehive.py).

The system uses TheHive as a case system of record. The integration is deliberately narrow:
- create case.
- add comment.
- close case.
- set case severity.
- read back the result to verify it landed.

A critical implementation detail is that TheHive 5 does not support a literal Closed status in the same way older flows might expect. Closing is implemented by setting a status whose stage is Closed and then verifying the resulting state.

### 5.7 Semantic memory layer
The memory subsystem is implemented in [agent-service/app/memory.py](../agent-service/app/memory.py).

The memory pipeline is the locked embedding path used throughout the project. It is important because changing the embedding model, dimension, or normalization logic would invalidate prior memory rows.

Key behaviors:
- One locked embedding path for both write and retrieval.
- Identity string generation is deterministic and used to form the memory identity.
- Memory rows are retrieved using hybrid similarity and recency logic.
- Memory edits can be analysis-only or identity-based, and the latter re-embeds the entry.

### 5.8 Operator API
The operator API is implemented in [agent-service/app/memory_api.py](../agent-service/app/memory_api.py) and [agent-service/app/ops_api.py](../agent-service/app/ops_api.py).

It is intended for automation and privileged maintenance tasks.

Protected endpoints include:
- listing memories.
- semantic search over memories.
- inspecting a memory row.
- editing memory analysis or identity.
- deleting a memory row.
- reconciliation between memory rows and investigation records.

Protection is via bearer-token authentication and is separate from analyst console authentication.

### 5.9 Analyst console
The console is implemented in [agent-service/app/console](../agent-service/app/console).

It is a server-rendered Jinja2/HTMX application, not a single-page app.

Key console capabilities:
- login and session-based access.
- triage queue view.
- investigation detail view.
- memory browsing and editing.
- verdict confirmation or override.
- triage feedback.
- TheHive case actions such as close, severity update, and comments.
- audit evidence for actions.

## 6. Database and data model

The data layer uses PostgreSQL with pgvector.

### Schema files
- [db/001_memory.sql](../db/001_memory.sql): semantic memory schema.
- [db/002_triage_dedup.sql](../db/002_triage_dedup.sql): deduplication state.
- [db/003_console.sql](../db/003_console.sql): analyst accounts, investigations, feedback, audit log.
- [db/004_chat.sql](../db/004_chat.sql): analyst chat data.
- [db/005_conversations.sql](../db/005_conversations.sql): analyst conversation history.
- [db/006_investigation_memory.sql](../db/006_investigation_memory.sql): investigation-memory linkage records.

### Important data semantics
- The investigation record is write-once.
- Analyst verdict overrides and triage feedback are stored separately from the original agent output.
- Audit log entries are mandatory for consequential analyst actions.
- Memory edits are audited before the mutation is applied.

## 7. Security model and guardrails

The project has a deliberately narrow security posture. It is not a broad enterprise security platform, but it does include several guardrails.

### Authentication planes
The system has three independent auth planes:
1. Analyst session authentication for the console.
2. Operator bearer-token authentication for the memory and ops APIs.
3. Webhook access through the network path only.

These are intentionally separate.

### Guardrails for the agent
The investigation agent is constrained to read-only tools only. It cannot perform destructive control actions.

The tool system is explicitly allowlisted and size-capped.

### Least-privilege Wazuh access
The agent queries Wazuh indexer data using a read-only user. That account is intended to be restricted to the alert index and not allowed to write or manage security state.

### Audit-first behavior
Consequence actions are not treated as anonymous. The system writes an audit row for actions taken through the console and for memory edits or case changes.

## 8. Request flow in detail

A single alert follows this path:

1. The Wazuh manager sends an alert to the webhook endpoint.
2. The FastAPI service receives the payload and normalizes it.
3. The alert identity is built and semantic memory is retrieved.
4. The agent investigates the alert using allowed read-only tools.
5. The agent output is structured into a locked schema.
6. The alert and analysis are written back to memory.
7. The deterministic triage router decides the action.
8. A write-once investigation record is stored for the console.
9. Analysts can review and act on the record through the console.

### What the webhook returns
The webhook response contains the structured analysis and metadata about the processing result. The application is designed to produce a deterministic response envelope even when some downstream components fail gracefully.

## 9. Operational notes

### Running the stack
The project is expected to be started through the provided startup script in [scripts/start-ramv2.sh](../scripts/start-ramv2.sh).

The stack uses Docker Compose and relies on local configuration files and environment variables.

### Bootstrap steps
Typical setup includes:
- copying the environment template to .env and filling in secrets.
- rendering TheHive configuration templates.
- rendering Wazuh config templates.
- generating certificates for Wazuh.
- bringing the containers up.
- bootstrapping TheHive and the indexer user.

### Important runtime caveats
- The agent service container image is built locally and the application code is baked into the image rather than live-mounted.
- Editing source files on disk will not immediately affect the running service unless the image is rebuilt and the container is restarted.
- The webhook is reachable on the host port and should be treated as network-exposed unless external firewall rules restrict it.
- The console and the memory API use separate authentication mechanisms.

## 10. Notable implementation details and constraints

### Locked behavior
Some pieces are intentionally locked and should not be casually modified:
- embedding model and dimension.
- memory identity format.
- output schema for the agent analysis.
- read-only tool policy.
- triage thresholds and routing logic.

Changing these without rethinking the downstream data model can break retrieval quality or historical consistency.

### Failure behavior
The system is designed to degrade gracefully rather than lose an alert:
- embedding or memory retrieval failure should not block the full workflow.
- the agent should still produce a fallback analysis if it cannot finish cleanly.
- console-record persistence failures are tracked and surfaced through reconciliation utilities.

### No active response
The system is not intended to perform active remediation. It does not isolate hosts, block IPs, kill processes, or alter endpoints. Its outward actions are limited to case management and internal data writes.

## 11. Useful entry points for future agents

If you need to understand or modify the repository, start here:
- [agent-service/app/main.py](../agent-service/app/main.py): routes and app wiring.
- [agent-service/app/webhook.py](../agent-service/app/webhook.py): end-to-end alert processing.
- [agent-service/app/agent.py](../agent-service/app/agent.py): bounded investigation loop.
- [agent-service/app/triage.py](../agent-service/app/triage.py): deterministic triage router.
- [agent-service/app/memory.py](../agent-service/app/memory.py): semantic memory pipeline.
- [agent-service/app/console/router.py](../agent-service/app/console/router.py): console routes and analyst actions.
- [agent-service/app/console/store.py](../agent-service/app/console/store.py): console persistence and audit logic.
- [db/003_console.sql](../db/003_console.sql): console schema and core data model.
- [docker-compose.yml](../docker-compose.yml): full service topology.

## 12. Suggested operational commands

These are examples of useful commands for working with the stack:

```bash
docker compose up -d
curl -X POST http://localhost:8000/webhook/wazuh -H 'Content-Type: application/json' --data @samples/wazuh_ssh_bruteforce.json
curl http://localhost:8000/health
```

For local development and rebuilds:

```bash
docker compose build agent-service
docker compose up -d agent-service
```

## 13. Known caveats to keep in mind

- The project is a single-environment, single-company deployment and should not be treated as a multi-tenant product.
- The webhook is not protected by a separate auth layer at the application level; its security is primarily network-based.
- The console and memory APIs are distinct and should not be conflated.
- The app code is baked into the agent-service image, so rebuilds are required for runtime changes.
- The semantic memory embedding pipeline is locked; changing it requires careful migration planning.
- The system is intended to assist triage, not replace a full incident-response platform.

## 14. Bottom line

RAM v2 is a focused, working SOC triage stack with a clear pipeline:

Wazuh alert -> AI investigation -> semantic memory -> deterministic triage -> TheHive case -> analyst review and audit.

It is best understood as a tightly scoped operational prototype with strong guardrails, explicit audit behavior, and a narrow but functional feature set. Any future changes should preserve those properties unless the project’s scope is intentionally expanded.
