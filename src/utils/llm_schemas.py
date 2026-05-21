"""
LLM Response Schema Validators

Pydantic models for post-parse validation of Gemini JSON responses.
Extra fields are ignored (extra="ignore") to avoid false rejections from
new LLM output.
"""
from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

_log = logging.getLogger(__name__)


class SecurityThreat(BaseModel):
    """Single security threat or CVE alert."""

    model_config = ConfigDict(extra="ignore")

    title: str
    ecosystem: str = "unknown"
    threat_level: str = "MEDIUM"
    summary: str = ""
    source_url: str
    action_required: str = "Review immediately"
    cve_id: Optional[str] = None
    fixed_version: Optional[str] = None

    @field_validator("ecosystem")
    @classmethod
    def _normalize_ecosystem(cls, v: str) -> str:
        _CANONICAL = {
            "supply chain": "supply-chain",
            "supply_chain": "supply-chain",
            "pypi": "PyPI",
            "pip": "PyPI",
        }
        return _CANONICAL.get(v.lower().strip(), v)

    @field_validator("source_url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if v and not v.startswith(("http://", "https://")):
            return ""
        return v


class SecurityTriageResponse(BaseModel):
    """Security threat triage response."""

    model_config = ConfigDict(extra="ignore")

    threats: list[SecurityThreat] = []


class SocialDrafts(BaseModel):
    """Social media drafts generated from the security digest."""

    model_config = ConfigDict(extra="ignore")

    reddit_title: str = ""
    reddit_body: str = ""
    twitter_thread: list[str] = []
    linkedin_post: str = ""


def log_validation_rejection(
    module: str,
    record_type: str,
    index: int,
    reason: str,
) -> None:
    """Log a validation rejection."""
    _log.warning(
        "[validation] module=%s record_type=%s index=%d reason=%s",
        module, record_type, index, reason,
    )
