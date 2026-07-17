"""Application configuration, loaded from environment variables (.env in compose).

Secrets are never hardcoded here — they come from the environment. See .env.example
for the variable names.
"""
# lru_cache remembers a function's return value so repeated calls skip the work.
# Here it guarantees Settings is built (and the environment parsed) only once.
from functools import lru_cache

# pydantic-settings ties configuration to environment variables: declare a field on a
# BaseSettings class and it is auto-filled from the matching env var (or .env file),
# with type conversion and validation for free. SettingsConfigDict tunes that behavior.
from pydantic_settings import BaseSettings, SettingsConfigDict


# One class holding ALL app configuration. Because it subclasses BaseSettings, each
# attribute below is read from an environment variable of the same name at startup.
# A field with no default is REQUIRED — the app refuses to start if it's missing,
# which surfaces misconfiguration immediately instead of hours later.
class Settings(BaseSettings):
    # model_config tunes how env vars are matched:
    #   case_sensitive=False — GEMINI_API_KEY and gemini_api_key both match this field.
    #   extra="ignore"       — unrelated env vars on the machine are simply ignored,
    #                          not treated as errors.
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- Gemini ---
    # Required: no default, so startup fails fast if the API key isn't set.
    gemini_api_key: str
    # Which Gemini model the agent loop calls.
    gemini_model: str = "gemini-2.5-flash"
    # Max seconds to wait on a Gemini API call before timing out.
    gemini_timeout: float = 60.0

    # --- VirusTotal ---
    # Required: no default, so startup fails fast if the API key isn't set.
    virustotal_api_key: str
    # Max seconds to wait on a VirusTotal API call before timing out.
    vt_timeout: float = 15.0
    vt_max_ips: int = 2  # cap how many IPs we enrich per alert

    # --- TheHive ---
    # Case creation is enabled only when an API key is present (Phase 4).
    # Base URL of the TheHive instance to create cases in.
    thehive_url: str = "http://thehive:9000"
    # Empty by default: case creation is disabled until an operator sets this (see thehive_enabled).
    thehive_api_key: str = ""
    # TheHive organisation/tenant to create cases under.
    thehive_organisation: str = "ram-v2"
    # Max seconds to wait on a TheHive API call before timing out.
    thehive_timeout: float = 20.0

    # --- Agent loop ---
    agent_max_iterations: int = 8  # bounded tool choice has more tools now

    # --- Wazuh Indexer (read-only investigation queries) ---
    # Base URL of the Wazuh Indexer (OpenSearch) used for read-only investigation queries.
    wazuh_indexer_url: str = "https://wazuh.indexer:9200"
    # Read-only username the agent uses to query the indexer.
    wazuh_indexer_ro_user: str = "ram_agent_ro"
    # Read-only password; empty default expects it to be supplied via env in real deployments.
    wazuh_indexer_ro_password: str = ""
    wazuh_indexer_ca_cert: str = "/certs/root-ca.pem"  # empty => skip TLS verify
    # Max seconds to wait on an indexer query before timing out.
    wazuh_indexer_timeout: float = 15.0

    # --- Investigation tool guardrails (cost/size caps) ---
    tool_max_result_chars: int = 8000   # cap any single tool result injected into prompt
    tool_max_hits: int = 10             # cap rows returned by indexer queries
    # Time window (minutes) used when looking up "related" alerts around an event.
    tool_related_window_minutes: int = 30
    tool_full_log_max_chars: int = 500  # truncate each full_log line
    tool_max_agg_buckets: int = 20      # cap buckets returned by aggregate queries

    # --- PostgreSQL (semantic memory) ---
    # Hostname of the Postgres server (service name in docker-compose).
    postgres_host: str = "postgres"
    # Postgres port, standard default.
    postgres_port: int = 5432
    # DB user for the memory schema.
    postgres_user: str = "ramv2"
    # DB password; empty default expects it to be supplied via env in real deployments.
    postgres_password: str = ""
    # Database name.
    postgres_db: str = "ramv2"

    # --- Semantic memory ---
    # LOCKED pipeline: changing model/dim/normalization requires re-embedding all rows.
    # Master switch: disabling skips retrieval/write-back entirely (alerts still get analyzed).
    memory_enabled: bool = True
    # Which embedding model produces the stored vectors.
    embedding_model: str = "gemini-embedding-001"
    # Vector dimensionality; must match the DB column and the embedding model's output.
    embedding_dim: int = 768
    # Embedding task type passed to the embedding API, tuned for similarity search.
    embedding_task_type: str = "SEMANTIC_SIMILARITY"
    memory_top_k: int = 5   # most-similar
    memory_recent_n: int = 5  # most-recent

    # A @property is a method you access like a plain attribute (settings.postgres_dsn,
    # no parentheses). This one derives the full DB connection string on the fly from
    # the individual host/port/user/... fields, so those stay the single source of truth.
    # A DSN (Data Source Name) is the single connection string a DB driver expects.
    @property
    def postgres_dsn(self) -> str:
        # Assemble a standard postgresql:// DSN from the discrete settings fields.
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # --- Logging ---
    # Root log level name (e.g. "INFO", "DEBUG"), consumed by configure_logging.
    agent_log_level: str = "INFO"

    # --- Operator API (memory endpoints, machine-to-machine only) ---
    # A "bearer token" is a secret string a caller puts in the Authorization header to
    # prove it's allowed in (like a password for machines, not humans). Required to call
    # /memory and /ops. Empty by default = fail closed: those endpoints reject everyone.
    operator_api_token: str = ""

    # --- Analyst console (session auth) ---
    # Secret key used to sign the console's session cookie; empty is insecure and should be set in prod.
    session_secret_key: str = ""
    # How long a console login session stays valid, in hours.
    session_max_age_hours: int = 8
    console_cookie_secure: bool = False  # set true behind TLS
    console_thehive_public_url: str = "http://localhost:9000/thehive"  # for case deep-links

    # --- Triage router (severity_score is on the locked 0-100 scale) ---
    triage_medium_threshold: int = 40   # score < this => low (auto-close)
    triage_high_threshold: int = 80     # score >= this => high (flag/escalate)
    # Time window (hours) used to detect and suppress duplicate alerts.
    triage_dedup_window_hours: float = 6.0
    triage_low_create_resolved_case: bool = False  # low: default no case (memory+log only)

    # Derived flag (a @property, see postgres_dsn above): TheHive case creation is
    # considered "on" only when an API key has actually been configured.
    @property
    def thehive_enabled(self) -> bool:
        # .strip() removes surrounding whitespace, so a key of "" or "   " both count as
        # not-configured; bool("") is False and bool("abc") is True.
        return bool(self.thehive_api_key.strip())


# get_settings() is THE way the rest of the app reads config. The @lru_cache decorator
# means the first call builds and validates Settings (reading the environment once) and
# every later call returns that same cached instance instantly.
@lru_cache
def get_settings() -> Settings:
    # Constructing Settings() triggers pydantic to read + validate every field from env.
    return Settings()
