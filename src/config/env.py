from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    NODE_ENV: str = "development"

    # ── LLM ──────────────────────────────────────────────────────────────────
    GEMINI_API_KEY: str
    GEMINI_MODEL: str = "gemini-2.5-flash-lite"
    GEMINI_API_BASE: str = "https://generativelanguage.googleapis.com/v1beta"

    # Optional context string injected at the top of every LLM prompt.
    LLM_GLOBAL_CONTEXT: str = ""

    # ── External APIs ────────────────────────────────────────────────────────
    GITHUB_TOKEN: str

    # ── Sources config ───────────────────────────────────────────────────────
    # Path to the YAML/JSON file that defines which threat intel feeds to fetch.
    SOURCES_CONFIG: str = "config/sources.yaml"

    # ── Security module settings ─────────────────────────────────────────────
    # Comma or newline-separated list of monitored packages.
    # Threats matching these are auto-escalated to CRITICAL + TOP_PRIORITY.
    SECURITY_MONITORED_PACKAGES: str = ""

    # Maximum number of intel items passed to the LLM for triage.
    SECURITY_MAX_TRIAGE_ITEMS: int = 80

    # Maximum number of threats included in the final output.
    SECURITY_MAX_ALERT_THREATS: int = 15

    @field_validator("GEMINI_API_BASE")
    @classmethod
    def _validate_gemini_base(cls, v: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError("GEMINI_API_BASE must use HTTPS")
        if not (parsed.hostname or "").endswith("googleapis.com"):
            raise ValueError("GEMINI_API_BASE must be a googleapis.com URL")
        return v


env = AppEnv()  # type: ignore[call-arg]
