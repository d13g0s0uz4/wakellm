from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)

from src.config.env import env
from src.config.sources_config import SourcesConfig
from src.gemini import GeminiService
from src.utils.llm_schemas import SecurityTriageResponse
from src.security_digest.fetchers import (
    fetch_github_advisories,
    fetch_reddit_json,
    fetch_rss_feeds,
    fetch_nvd_cves,
    fetch_cisa_kev,
)
from src.security_digest.intel import (
    _normalize_intel,
    _prioritize_intel_for_triage,
    _fallback_threats_from_intel,
    _enrich_threats,
    _select_alert_threats,
)
from src.security_digest.monitored import (
    _parse_monitored_packages,
    _apply_monitored_priority,
)
from src.security_digest.prompts import get_security_triage_prompt
from src.security_digest.utils import (
    _normalize_cve_id,
    _normalize_optional_text,
    _normalize_threat_level,
)


async def run_security_digest() -> None:
    async def _empty() -> list:
        return []

    _log.info("=== STARTING SECURITY DIGEST PIPELINE ===")

    sources = SourcesConfig.load(env.SOURCES_CONFIG)
    gemini = GeminiService()
    monitored_packages = _parse_monitored_packages(env.SECURITY_MONITORED_PACKAGES or None)

    fetch_tasks = [
        fetch_github_advisories(sources.github_advisories.ecosystems, sources.github_advisories.per_page)
        if sources.github_advisories.enabled else _empty(),
        fetch_reddit_json(sources.reddit.subreddits)
        if sources.reddit.enabled else _empty(),
        fetch_rss_feeds([f.url for f in sources.rss_feeds.feeds])
        if sources.rss_feeds.enabled and sources.rss_feeds.feeds else _empty(),
        fetch_nvd_cves(sources.nvd.api_url)
        if sources.nvd.enabled else _empty(),
        fetch_cisa_kev(sources.cisa_kev.feed_url)
        if sources.cisa_kev.enabled else _empty(),
    ]

    github_items, reddit_items, rss_items, nvd_items, cisa_items = await asyncio.gather(*fetch_tasks)
    _log.info(
        "[fetch] github=%d reddit=%d rss=%d nvd=%d cisa=%d",
        len(github_items), len(reddit_items), len(rss_items), len(nvd_items), len(cisa_items),
    )

    intel_items = _normalize_intel(github_items + reddit_items + rss_items + nvd_items + cisa_items)
    intel_url_set = {item["url"].strip() for item in intel_items if item.get("url")}
    intel_by_cve = {
        item["cve_id"]: item["url"]
        for item in intel_items
        if item.get("cve_id") and item.get("url")
    }
    if not intel_items:
        _log.warning("No security intelligence items collected.")
        output = {"run_at": datetime.now(timezone.utc).isoformat(), "threats": []}
        print(json.dumps(output, indent=2))
        return

    triage_intel = _prioritize_intel_for_triage(intel_items)
    prompt_intel = [
        {"title": i["title"], "url": i["url"], "body": i["snippet"], "cve_id": i["cve_id"]}
        for i in triage_intel
    ]
    triage_prompt = get_security_triage_prompt(
        json.dumps(prompt_intel),
        monitored_packages=monitored_packages,
        global_context=env.LLM_GLOBAL_CONTEXT.strip(),
    )

    triage_response: SecurityTriageResponse | None = None
    triage_failed = False
    try:
        triage_response = await gemini.generate_json(
            triage_prompt,
            schema=SecurityTriageResponse,
            use_search=False,
            temperature=0.1,
        )
    except Exception as exc:
        triage_failed = True
        _log.warning("Security triage failed; falling back to CVE-based deterministic parsing: %s", exc)

    raw_threats = triage_response.threats if triage_response is not None else []
    threats: list[dict[str, Any]] = []

    for threat_idx, threat in enumerate(raw_threats):
        title = threat.title or ""
        source_url = threat.source_url or ""
        if not title or not source_url:
            _log.warning("Skipping threat %d: missing title or source_url", threat_idx)
            continue

        if source_url not in intel_url_set:
            cve_key = _normalize_cve_id(threat.cve_id) or ""
            recovered = intel_by_cve.get(cve_key) if cve_key else None
            if recovered:
                _log.info("[triage] Hallucinated URL recovered via CVE for threat %d: %r \u2192 %r", threat_idx, source_url, recovered)
                source_url = recovered
            else:
                _log.warning("[triage] Dropping threat %d: unrecoverable hallucinated URL %r", threat_idx, source_url)
                continue

        threats.append(
            {
                "title": title,
                "ecosystem": threat.ecosystem or "unknown",
                "threat_level": _normalize_threat_level(threat.threat_level or "MEDIUM"),
                "summary": threat.summary or "",
                "source_url": source_url,
                "action_required": threat.action_required or "Review immediately",
                "cve_id": _normalize_cve_id(threat.cve_id) or "",
                "fixed_version": _normalize_optional_text(threat.fixed_version) or "",
            }
        )

    if triage_failed and not threats:
        threats = _fallback_threats_from_intel(triage_intel)
        if threats:
            _log.info("Fallback produced %d threat candidates from direct CVE intel.", len(threats))

    threats = _enrich_threats(threats, intel_items)
    threats = _apply_monitored_priority(threats, monitored_packages)
    threats = _select_alert_threats(threats)

    _SENTINEL_KEYS = {"matched_package", "priority_tag"}
    output_threats = [
        {k: v for k, v in t.items() if not (k in _SENTINEL_KEYS and v == "")}
        for t in threats
    ]
    output = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "threats": output_threats,
    }
    print(json.dumps(output, indent=2))
