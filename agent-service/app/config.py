"""Application configuration, loaded from environment variables (.env in compose).

Secrets are never hardcoded here — they come from the environment. See .env.example
for the variable names.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- Gemini ---
    gemini_api_key: str
    gemini_model: str = "gemini-2.0-flash"
    gemini_timeout: float = 60.0

    # --- VirusTotal ---
    virustotal_api_key: str
    vt_timeout: float = 15.0
    vt_max_ips: int = 2  # cap how many IPs we enrich per alert

    # --- TheHive ---
    # Case creation is enabled only when an API key is present (Phase 4).
    thehive_url: str = "http://thehive:9000"
    thehive_api_key: str = ""
    thehive_organisation: str = "ram-v2"
    thehive_timeout: float = 20.0

    # --- Agent loop ---
    agent_max_iterations: int = 3

    # --- PostgreSQL (semantic memory) ---
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "ramv2"
    postgres_password: str = ""
    postgres_db: str = "ramv2"

    # --- Semantic memory ---
    # LOCKED pipeline: changing model/dim/normalization requires re-embedding all rows.
    memory_enabled: bool = True
    embedding_model: str = "gemini-embedding-001"
    embedding_dim: int = 768
    embedding_task_type: str = "SEMANTIC_SIMILARITY"
    memory_top_k: int = 5   # most-similar
    memory_recent_n: int = 5  # most-recent

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # --- Logging ---
    agent_log_level: str = "INFO"

    # --- Operator API (memory endpoints) ---
    operator_api_token: str = ""

    # --- Triage router (severity_score is on the locked 0-100 scale) ---
    triage_medium_threshold: int = 40   # score < this => low (auto-close)
    triage_high_threshold: int = 80     # score >= this => high (flag/escalate)
    triage_dedup_window_hours: float = 6.0
    triage_low_create_resolved_case: bool = False  # low: default no case (memory+log only)

    @property
    def thehive_enabled(self) -> bool:
        return bool(self.thehive_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
