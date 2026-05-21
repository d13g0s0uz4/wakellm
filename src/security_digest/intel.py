from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.security_digest.utils import (
    _build_dedup_key,
    _normalize_cve_id,
    _normalize_optional_text,
)

_MAX_TRIAGE_INTEL_ITEMS = 40
_MAX_ALERT_THREATS = 10


def _normalize_intel(items: list[dict[str, str]]) -> list[dict[str, str]]:
    # First pass: deduplicate by url|title.
    unique: dict[str, dict[str, str]] = {}
    for item in items:
        title = item.get("title", "").strip().lower()
        url = item.get("url", "").strip()
        if not title or not url:
            continue
        key = f"{url}|{title}"
        if key not in unique:
            unique[key] = item

    # Second pass: deduplicate by CVE ID, keeping the highest-authority source.
    # Authority: CISA KEV (0) > NIST NVD (1) > GitHub Advisory (2) > others (99)
    _AUTHORITY: dict[str, int] = {"CISA KEV": 0, "NIST NVD": 1, "GitHub Advisory": 2}
    by_cve: dict[str, dict[str, str]] = {}
    deduped: list[dict[str, str]] = []
    for item in unique.values():
        cve_id = _normalize_cve_id(item.get("cve_id") or "")
        if not cve_id:
            deduped.append(item)
            continue
        if cve_id not in by_cve:
            by_cve[cve_id] = item
        else:
            existing_rank = _AUTHORITY.get(by_cve[cve_id].get("source") or "", 99)
            new_rank = _AUTHORITY.get(item.get("source") or "", 99)
            if new_rank < existing_rank:
                by_cve[cve_id] = item

    deduped.extend(by_cve.values())
    return deduped


def _prioritize_intel_for_triage(intel_items: list[dict[str, str]]) -> list[dict[str, str]]:
    source_rank = {
        "CISA KEV": 0,
        "NIST NVD": 1,
        "GitHub Advisory": 2,
    }

    def _rank(item: dict[str, str]) -> tuple[int, int, float]:
        source = str(item.get("source") or "")
        ecosystem = str(item.get("ecosystem_hint") or "")
        cve_id = str(item.get("cve_id") or "")
        published = str(item.get("published_at") or "")

        source_priority = source_rank.get(source, 3)
        ecosystem_priority = 0 if ecosystem in {"npm", "PyPI", "supply-chain"} else 1
        cve_priority = 0 if cve_id else 1
        try:
            recency = -datetime.fromisoformat(published.replace("Z", "+00:00")).timestamp()
        except Exception:
            recency = 0.0
        return (source_priority, ecosystem_priority + cve_priority, recency)

    prioritized = sorted(intel_items, key=_rank)
    return prioritized[:_MAX_TRIAGE_INTEL_ITEMS]


def _fallback_threats_from_intel(intel_items: list[dict[str, str]]) -> list[dict[str, Any]]:
    fallback: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for item in intel_items:
        source_url = str(item.get("url") or "").strip()
        title = str(item.get("title") or "").strip()
        cve_id = _normalize_cve_id(str(item.get("cve_id") or ""))
        if not source_url or not title or not cve_id:
            continue
        if source_url in seen_urls:
            continue
        seen_urls.add(source_url)

        source = str(item.get("source") or "")
        threat_level = "CRITICAL" if source == "CISA KEV" else "HIGH"
        ecosystem = str(item.get("ecosystem_hint") or "unknown")
        if ecosystem not in {"npm", "PyPI", "supply-chain"}:
            ecosystem = "unknown"

        fallback.append(
            {
                "title": title,
                "ecosystem": ecosystem,
                "threat_level": threat_level,
                "summary": str(item.get("snippet") or "")[:500],
                "source_url": source_url,
                "action_required": "Review dependency exposure and patch plan immediately",
                "cve_id": cve_id,
                "fixed_version": _normalize_optional_text(str(item.get("fixed_version") or "")) or "",
            }
        )

    return fallback


def _select_alert_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    top_priority = [t for t in threats if t.get("priority_tag") == "TOP_PRIORITY"]
    critical = [
        t
        for t in threats
        if t.get("threat_level") == "CRITICAL" and t.get("priority_tag") != "TOP_PRIORITY"
    ]
    high = [t for t in threats if t.get("threat_level") == "HIGH"]

    selected = [*top_priority, *critical]
    if len(selected) >= _MAX_ALERT_THREATS:
        return selected[:_MAX_ALERT_THREATS]

    return [*selected, *high[: _MAX_ALERT_THREATS - len(selected)]]


def _enrich_threats(threats: list[dict[str, Any]], intel_items: list[dict[str, str]]) -> list[dict[str, Any]]:
    intel_by_url = {item.get("url", "").strip(): item for item in intel_items if item.get("url")}
    enriched: list[dict[str, Any]] = []

    for threat in threats:
        source_item = intel_by_url.get(str(threat.get("source_url") or "").strip(), {})
        cve_id = _normalize_cve_id(str(threat.get("cve_id") or source_item.get("cve_id") or ""))
        fixed_version = _normalize_optional_text(str(threat.get("fixed_version") or source_item.get("fixed_version") or ""))
        source_url = str(threat.get("source_url") or "").strip()
        title = str(threat.get("title") or "").strip()

        enriched.append(
            {
                **threat,
                "cve_id": cve_id or "",
                "fixed_version": fixed_version or "",
                "dedup_key": _build_dedup_key(cve_id, source_url, title),
                "status": "OPEN",
            }
        )

    return enriched
