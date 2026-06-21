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

    # --- Logging ---
    agent_log_level: str = "INFO"

    @property
    def thehive_enabled(self) -> bool:
        return bool(self.thehive_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
