from __future__ import annotations

import os
import unittest
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("GEMINI_API_KEY", "test-gemini-key")
os.environ.setdefault("GITHUB_TOKEN", "test-github-token")

from src.security_digest import (
    _apply_monitored_priority,
    _build_dedup_key,
    _fallback_threats_from_intel,
    _find_monitored_package_match,
    _normalize_threat_level,
    _parse_monitored_packages,
    _prioritize_intel_for_triage,
    _select_alert_threats,
)


def _make_threat(**kwargs: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "title": "Test threat",
        "ecosystem": "npm",
        "threat_level": "HIGH",
        "summary": "A vulnerability was found.",
        "source_url": "https://example.com/advisory/1",
        "action_required": "Review immediately",
        "cve_id": None,
        "fixed_version": None,
        "priority_tag": "",
        "matched_package": "",
    }
    return {**defaults, **kwargs}


# ── _parse_monitored_packages ─────────────────────────────────────────────────

class ParseMonitoredPackagesTests(unittest.TestCase):
    def test_json_array_input(self) -> None:
        result = _parse_monitored_packages('["react", "lodash", "express"]')
        self.assertEqual(result, ["react", "lodash", "express"])

    def test_csv_input(self) -> None:
        result = _parse_monitored_packages("react, lodash, express")
        self.assertEqual(result, ["react", "lodash", "express"])

    def test_newline_input(self) -> None:
        result = _parse_monitored_packages("react\nlodash\nexpress")
        self.assertEqual(result, ["react", "lodash", "express"])

    def test_empty_input(self) -> None:
        self.assertEqual(_parse_monitored_packages(""), [])
        self.assertEqual(_parse_monitored_packages(None), [])
        self.assertEqual(_parse_monitored_packages("   "), [])

    def test_deduplicates(self) -> None:
        result = _parse_monitored_packages("react, react, lodash")
        self.assertEqual(result, ["react", "lodash"])

    def test_normalizes_to_lowercase(self) -> None:
        result = _parse_monitored_packages("React, Lodash")
        self.assertEqual(result, ["react", "lodash"])


# ── _find_monitored_package_match ─────────────────────────────────────────────

class FindMonitoredPackageMatchTests(unittest.TestCase):
    def test_exact_title_match(self) -> None:
        threat = _make_threat(title="Malicious package 'lodash' on npm")
        result = _find_monitored_package_match(threat, ["lodash"])
        self.assertEqual(result, "lodash")

    def test_no_match_word_boundary(self) -> None:
        threat = _make_threat(title="Vulnerability in react-dom component")
        result = _find_monitored_package_match(threat, ["react"])
        # "react" should not match "react-dom" because '-' is treated as a separator
        # The regex uses [^a-z0-9@/_.-] so '-' IS in the allowed continuation chars
        # meaning react-dom would NOT trigger a match for 'react' on the right boundary
        # because '-' is in the exclusion class ([^a-z0-9@/_.-])
        # Let's just check it matches or not correctly based on actual implementation
        self.assertIsNone(result)

    def test_match_in_summary(self) -> None:
        threat = _make_threat(title="Critical vulnerability", summary="affects lodash package")
        result = _find_monitored_package_match(threat, ["lodash"])
        self.assertEqual(result, "lodash")

    def test_no_packages_returns_none(self) -> None:
        threat = _make_threat(title="lodash vulnerability")
        result = _find_monitored_package_match(threat, [])
        self.assertIsNone(result)


# ── _apply_monitored_priority ─────────────────────────────────────────────────

class ApplyMonitoredPriorityTests(unittest.TestCase):
    def test_escalates_to_critical(self) -> None:
        threats = [_make_threat(title="lodash RCE", threat_level="HIGH")]
        result = _apply_monitored_priority(threats, ["lodash"])
        self.assertEqual(result[0]["threat_level"], "CRITICAL")

    def test_sets_top_priority_tag(self) -> None:
        threats = [_make_threat(title="lodash RCE")]
        result = _apply_monitored_priority(threats, ["lodash"])
        self.assertEqual(result[0]["priority_tag"], "TOP_PRIORITY")

    def test_prefixes_action_required(self) -> None:
        threats = [_make_threat(title="lodash RCE", action_required="Patch now")]
        result = _apply_monitored_priority(threats, ["lodash"])
        self.assertIn("Top priority:", result[0]["action_required"])
        self.assertIn("lodash", result[0]["action_required"])

    def test_non_matching_threats_unchanged(self) -> None:
        threats = [_make_threat(title="random threat")]
        result = _apply_monitored_priority(threats, ["lodash"])
        self.assertEqual(result[0]["threat_level"], "HIGH")
        self.assertEqual(result[0]["priority_tag"], "")

    def test_does_not_duplicate_top_priority_prefix(self) -> None:
        action = "Top priority: already set. Patch now"
        threats = [_make_threat(title="lodash RCE", action_required=action)]
        result = _apply_monitored_priority(threats, ["lodash"])
        self.assertNotIn("Top priority: Top priority:", result[0]["action_required"])


# ── _build_dedup_key ──────────────────────────────────────────────────────────

class BuildDedupKeyTests(unittest.TestCase):
    def test_cve_key_wins_over_url_title(self) -> None:
        key = _build_dedup_key("CVE-2024-12345", "https://example.com/advisory", "Some vuln")
        self.assertEqual(key, "CVE-2024-12345")

    def test_url_title_fallback_when_no_cve(self) -> None:
        key = _build_dedup_key(None, "https://example.com/advisory", "Some Vuln")
        self.assertEqual(key, "https://example.com/advisory|some vuln")

    def test_cve_normalized_to_uppercase(self) -> None:
        key = _build_dedup_key("cve-2024-12345", "https://example.com", "title")
        self.assertEqual(key, "CVE-2024-12345")

    def test_cve_extracted_from_embedded_text(self) -> None:
        key = _build_dedup_key("See CVE-2024-99999 for details", "https://x.com", "t")
        self.assertEqual(key, "CVE-2024-99999")


# ── _fallback_threats_from_intel ──────────────────────────────────────────────

class FallbackThreatsFromIntelTests(unittest.TestCase):
    def test_only_cve_bearing_items(self) -> None:
        items = [
            {"url": "https://a.com", "title": "No CVE item", "cve_id": "", "source": "Reddit", "snippet": "x", "fixed_version": ""},
            {"url": "https://b.com", "title": "CVE item", "cve_id": "CVE-2024-1234", "source": "NIST NVD", "snippet": "y", "fixed_version": "", "ecosystem_hint": "npm"},
        ]
        result = _fallback_threats_from_intel(items)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2024-1234")

    def test_cisa_kev_gets_critical(self) -> None:
        items = [{"url": "https://cisa.gov/kev", "title": "KEV item", "cve_id": "CVE-2024-5678", "source": "CISA KEV", "snippet": "", "fixed_version": "", "ecosystem_hint": ""}]
        result = _fallback_threats_from_intel(items)
        self.assertEqual(result[0]["threat_level"], "CRITICAL")

    def test_others_get_high(self) -> None:
        items = [{"url": "https://nvd.nist.gov/1", "title": "NVD item", "cve_id": "CVE-2024-9999", "source": "NIST NVD", "snippet": "", "fixed_version": "", "ecosystem_hint": ""}]
        result = _fallback_threats_from_intel(items)
        self.assertEqual(result[0]["threat_level"], "HIGH")

    def test_deduplicates_by_url(self) -> None:
        items = [
            {"url": "https://same.com", "title": "Duplicate", "cve_id": "CVE-2024-1111", "source": "NIST NVD", "snippet": "", "fixed_version": "", "ecosystem_hint": ""},
            {"url": "https://same.com", "title": "Duplicate 2", "cve_id": "CVE-2024-2222", "source": "NIST NVD", "snippet": "", "fixed_version": "", "ecosystem_hint": ""},
        ]
        result = _fallback_threats_from_intel(items)
        self.assertEqual(len(result), 1)


# ── _select_alert_threats ─────────────────────────────────────────────────────

class SelectAlertThreatsTests(unittest.TestCase):
    def test_top_priority_first(self) -> None:
        threats = [
            _make_threat(threat_level="HIGH", priority_tag=""),
            _make_threat(threat_level="CRITICAL", priority_tag="TOP_PRIORITY", title="Top one"),
        ]
        result = _select_alert_threats(threats)
        self.assertEqual(result[0]["title"], "Top one")

    def test_ceiling_of_15(self) -> None:
        threats = [_make_threat(threat_level="HIGH", title=f"item {i}") for i in range(20)]
        result = _select_alert_threats(threats)
        self.assertLessEqual(len(result), 15)

    def test_high_fills_remaining_slots(self) -> None:
        top = [_make_threat(threat_level="CRITICAL", priority_tag="TOP_PRIORITY") for _ in range(3)]
        high = [_make_threat(threat_level="HIGH", title=f"high {i}") for i in range(10)]
        result = _select_alert_threats([*top, *high])
        high_in_result = [t for t in result if t.get("threat_level") == "HIGH"]
        self.assertGreater(len(high_in_result), 0)
        self.assertLessEqual(len(result), 15)


# ── _normalize_threat_level ───────────────────────────────────────────────────

class NormalizeThreatLevelTests(unittest.TestCase):
    def test_valid_critical_passes_through(self) -> None:
        self.assertEqual(_normalize_threat_level("CRITICAL"), "CRITICAL")

    def test_valid_high_passes_through(self) -> None:
        self.assertEqual(_normalize_threat_level("HIGH"), "HIGH")

    def test_valid_medium_passes_through(self) -> None:
        self.assertEqual(_normalize_threat_level("MEDIUM"), "MEDIUM")

    def test_unknown_level_becomes_medium(self) -> None:
        self.assertEqual(_normalize_threat_level("CATASTROPHIC"), "MEDIUM")

    def test_empty_string_becomes_medium(self) -> None:
        self.assertEqual(_normalize_threat_level(""), "MEDIUM")

    def test_lowercase_accepted(self) -> None:
        self.assertEqual(_normalize_threat_level("critical"), "CRITICAL")


# ── _prioritize_intel_for_triage ──────────────────────────────────────────────

class PrioritizeIntelForTriageTests(unittest.TestCase):
    def test_cisa_kev_ranks_first(self) -> None:
        items = [
            {"source": "Reddit", "cve_id": "", "ecosystem_hint": "", "published_at": "2024-01-01", "title": "Reddit item", "url": "https://r.com", "snippet": ""},
            {"source": "CISA KEV", "cve_id": "CVE-2024-999", "ecosystem_hint": "", "published_at": "2024-01-01", "title": "CISA item", "url": "https://c.com", "snippet": ""},
            {"source": "NIST NVD", "cve_id": "CVE-2024-888", "ecosystem_hint": "", "published_at": "2024-01-01", "title": "NVD item", "url": "https://n.com", "snippet": ""},
        ]
        result = _prioritize_intel_for_triage(items)
        self.assertEqual(result[0]["source"], "CISA KEV")

    def test_nvd_before_github_advisory(self) -> None:
        items = [
            {"source": "GitHub Advisory", "cve_id": "CVE-2024-111", "ecosystem_hint": "npm", "published_at": "2024-01-01", "title": "GH item", "url": "https://gh.com", "snippet": ""},
            {"source": "NIST NVD", "cve_id": "CVE-2024-222", "ecosystem_hint": "npm", "published_at": "2024-01-01", "title": "NVD item", "url": "https://nvd.com", "snippet": ""},
        ]
        result = _prioritize_intel_for_triage(items)
        self.assertEqual(result[0]["source"], "NIST NVD")

    def test_truncates_to_120_items(self) -> None:
        items = [
            {"source": "Reddit", "cve_id": "", "ecosystem_hint": "", "published_at": "2024-01-01", "title": f"Item {i}", "url": f"https://r.com/{i}", "snippet": ""}
            for i in range(200)
        ]
        result = _prioritize_intel_for_triage(items)
        self.assertEqual(len(result), 120)


if __name__ == "__main__":
    unittest.main()
