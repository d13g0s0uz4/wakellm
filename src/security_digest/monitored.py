from __future__ import annotations

import functools
import json
import re
from typing import Any


def _parse_monitored_packages(raw: str | None) -> list[str]:
    if not raw:
        return []

    value = raw.strip()
    if not value:
        return []

    parsed_values: list[str] = []
    if value.startswith("[") or value.startswith("{"):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                parsed_values = [str(item) for item in parsed]
            elif isinstance(parsed, dict) and isinstance(parsed.get("packages"), list):
                parsed_values = [str(item) for item in parsed["packages"]]
        except Exception:
            parsed_values = []

    if not parsed_values:
        parsed_values = re.split(r"[;,\n]", value)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in parsed_values:
        normalized = item.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def _escape_regex(value: str) -> str:
    return re.escape(value)


@functools.lru_cache(maxsize=256)
def _compile_pkg_pattern(pkg: str) -> re.Pattern[str]:
    return re.compile(rf"(^|[^a-z0-9@/_.-]){_escape_regex(pkg)}($|[^a-z0-9@/_.-])", re.IGNORECASE)


def _find_monitored_package_match(threat: dict[str, Any], monitored_packages: list[str]) -> str | None:
    if not monitored_packages:
        return None

    searchable_text = " ".join(
        [
            str(threat.get("title") or ""),
            str(threat.get("summary") or ""),
            str(threat.get("action_required") or ""),
            str(threat.get("source_url") or ""),
        ]
    ).lower()

    for pkg in monitored_packages:
        if _compile_pkg_pattern(pkg).search(searchable_text):
            return pkg

    return None


def _apply_monitored_priority(
    threats: list[dict[str, Any]],
    monitored_packages: list[str],
) -> list[dict[str, Any]]:
    # Compile all patterns (lru_cache means this is free on repeat calls).
    compiled = [(pkg, _compile_pkg_pattern(pkg)) for pkg in monitored_packages]

    updated: list[dict[str, Any]] = []
    for threat in threats:
        matched_package: str | None = None
        if compiled:
            searchable_text = " ".join(
                [
                    str(threat.get("title") or ""),
                    str(threat.get("summary") or ""),
                    str(threat.get("action_required") or ""),
                    str(threat.get("source_url") or ""),
                ]
            ).lower()
            for pkg, pattern in compiled:
                if pattern.search(searchable_text):
                    matched_package = pkg
                    break

        if not matched_package:
            updated.append({**threat, "matched_package": "", "priority_tag": ""})
            continue

        action_required = str(threat.get("action_required") or "Review immediately")
        if "Top priority" not in action_required:
            action_required = (
                f"Top priority: vulnerable dependency present in monitored package list ({matched_package}). "
                f"{action_required}"
            )

        updated.append(
            {
                **threat,
                "threat_level": "CRITICAL",
                "action_required": action_required,
                "matched_package": matched_package,
                "priority_tag": "TOP_PRIORITY",
            }
        )

    return updated
