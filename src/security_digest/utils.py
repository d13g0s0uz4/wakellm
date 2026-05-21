from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

_log = logging.getLogger(__name__)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _infer_ecosystem(text: str) -> str:
    t = text.lower()
    if "pypi" in t or "pip" in t:
        return "PyPI"
    if "npm" in t or "node" in t:
        return "npm"
    if "supply chain" in t or "typosquatting" in t or "malicious package" in t:
        return "supply-chain"
    return "unknown"


def _safe_iso_date(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).isoformat()
    except Exception as exc:
        _log.warning("Bad date value %r: %s", value, exc)
        return datetime.now(timezone.utc).isoformat()


def _normalize_cve_id(value: str | None) -> str | None:
    if not value:
        return None
    match = _CVE_RE.search(value)
    return match.group(0).upper() if match else None


def _extract_cve_id(*values: str | None) -> str | None:
    for value in values:
        cve_id = _normalize_cve_id(value)
        if cve_id:
            return cve_id
    return None


def _build_dedup_key(cve_id: str | None, source_url: str, title: str) -> str:
    normalized_cve = _normalize_cve_id(cve_id)
    if normalized_cve:
        return normalized_cve
    return f"{source_url.strip()}|{title.strip().lower()}"


def _normalize_optional_text(value: str | None) -> str | None:
    if not value:
        return None
    trimmed = value.strip()
    return trimmed or None


def _normalize_threat_level(level: str) -> str:
    upper = (level or "").upper()
    if upper in {"CRITICAL", "HIGH", "MEDIUM"}:
        return upper
    return "MEDIUM"
