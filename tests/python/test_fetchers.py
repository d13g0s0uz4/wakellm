from __future__ import annotations

import asyncio
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("GEMINI_API_KEY", "test-gemini-key")
os.environ.setdefault("GITHUB_TOKEN", "test-github-token")

from src.security_digest.fetchers import (
    fetch_cisa_kev,
    fetch_github_advisories,
    fetch_nvd_cves,
    fetch_reddit_json,
    fetch_rss_feeds,
    _infer_ecosystem_from_nvd,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _mock_response(status_code: int = 200, json_data=None, text: str | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
        resp.text = text if text is not None else str(json_data)
    else:
        resp.json.return_value = {}
        resp.text = text or ""
    resp.url = "https://example.com"
    return resp


# ── fetch_github_advisories ────────────────────────────────────────────────────

class FetchGithubAdvisoriesTests(unittest.TestCase):
    def _make_advisory(self, cve_id="CVE-2024-1234", ecosystem="npm"):
        return {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": cve_id,
            "summary": f"Test advisory for {ecosystem}",
            "description": "A vulnerability was found.",
            "html_url": f"https://github.com/advisories/GHSA-xxxx-{ecosystem}",
            "published_at": "2024-01-15T00:00:00Z",
            "vulnerabilities": [
                {"first_patched_version": {"identifier": "1.2.3"}}
            ],
        }

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_success_returns_items(self, mock_client_cls):
        advisory = self._make_advisory()
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, [advisory]))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_github_advisories(["npm"]))

        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["source"], "GitHub Advisory")
        self.assertEqual(item["cve_id"], "CVE-2024-1234")
        self.assertEqual(item["fixed_version"], "1.2.3")
        self.assertTrue(item["url"].startswith("https://"))

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_http_error_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(403, text="Forbidden"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_github_advisories(["npm"]))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_network_exception_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_github_advisories(["npm"]))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_empty_list_response(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, []))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_github_advisories(["npm", "pip"]))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_multiple_ecosystems_merged(self, mock_client_cls):
        npm_advisory = self._make_advisory("CVE-2024-0001", "npm")
        pip_advisory = self._make_advisory("CVE-2024-0002", "pip")
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=[
            _mock_response(200, [npm_advisory]),
            _mock_response(200, [pip_advisory]),
        ])
        mock_client_cls.return_value = mock_client

        items = _run(fetch_github_advisories(["npm", "pip"]))
        self.assertEqual(len(items), 2)


# ── fetch_reddit_json ──────────────────────────────────────────────────────────

class FetchRedditJsonTests(unittest.TestCase):
    def _make_post(self, title="Malicious npm package found", subreddit="netsec"):
        return {
            "kind": "t3",
            "data": {
                "title": title,
                "selftext": "Details about the package.",
                "url": "https://reddit.com/r/netsec/comments/abc123",
                "permalink": "/r/netsec/comments/abc123",
                "subreddit": subreddit,
                "created_utc": 1700000000.0,
            },
        }

    def _reddit_response(self, posts):
        return {"data": {"children": posts}}

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_success_returns_items(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(
            200, self._reddit_response([self._make_post()])
        ))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_reddit_json(["netsec"]))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Malicious npm package found")

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_403_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(403, text="Forbidden"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_reddit_json(["netsec"]))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_empty_children_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, {"data": {"children": []}}))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_reddit_json(["netsec"]))
        self.assertEqual(items, [])


# ── fetch_rss_feeds ────────────────────────────────────────────────────────────

_SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>Malicious PyPI package detected</title>
      <link>https://example.com/blog/pypi-malware</link>
      <description>A typosquatting attack targeting PyPI users.</description>
      <pubDate>Mon, 15 Jan 2024 12:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>"""

_EMPTY_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Empty</title></channel></rss>"""


class FetchRssFeedsTests(unittest.TestCase):
    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_success_returns_items(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        resp = _mock_response(200, text=_SAMPLE_RSS)
        resp.text = _SAMPLE_RSS
        mock_client.get = AsyncMock(return_value=resp)
        mock_client_cls.return_value = mock_client

        items = _run(fetch_rss_feeds(["https://example.com/rss"]))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Malicious PyPI package detected")
        self.assertEqual(items[0]["url"], "https://example.com/blog/pypi-malware")

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_http_error_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(500, text=""))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_rss_feeds(["https://example.com/rss"]))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_malformed_xml_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<not valid xml <<<"
        mock_client.get = AsyncMock(return_value=resp)
        mock_client_cls.return_value = mock_client

        items = _run(fetch_rss_feeds(["https://example.com/rss"]))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_empty_feed_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = _EMPTY_RSS
        mock_client.get = AsyncMock(return_value=resp)
        mock_client_cls.return_value = mock_client

        items = _run(fetch_rss_feeds(["https://example.com/rss"]))
        self.assertEqual(items, [])


# ── fetch_nvd_cves ─────────────────────────────────────────────────────────────

class FetchNvdCvesTests(unittest.TestCase):
    def _make_nvd_payload(self, cve_id="CVE-2024-5678"):
        return {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "published": "2024-01-15T10:00:00.000",
                        "descriptions": [
                            {"lang": "en", "value": "A critical vulnerability in npm package."}
                        ],
                    }
                }
            ],
        }

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_success_returns_items(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, self._make_nvd_payload()))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_nvd_cves("https://services.nvd.nist.gov/rest/json/cves/2.0"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cve_id"], "CVE-2024-5678")
        self.assertEqual(items[0]["source"], "NIST NVD")
        self.assertTrue(items[0]["url"].startswith("https://nvd.nist.gov/"))

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_http_error_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(429, text="Too Many Requests"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_nvd_cves("https://services.nvd.nist.gov/rest/json/cves/2.0"))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_network_exception_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=Exception("Timeout"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_nvd_cves("https://services.nvd.nist.gov/rest/json/cves/2.0"))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_empty_vulnerabilities_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, {"vulnerabilities": []}))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_nvd_cves("https://services.nvd.nist.gov/rest/json/cves/2.0"))
        self.assertEqual(items, [])


# ── fetch_cisa_kev ─────────────────────────────────────────────────────────────

class FetchCisaKevTests(unittest.TestCase):
    def _make_kev_payload(self, cve_id="CVE-2023-9999"):
        return {
            "title": "CISA KEV Catalog",
            "vulnerabilities": [
                {
                    "cveID": cve_id,
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "shortDescription": "Remote code execution vulnerability.",
                    "dateAdded": "2023-12-01",
                    "knownRansomwareCampaignUse": "Known",
                }
            ],
        }

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_success_returns_items(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, self._make_kev_payload()))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_cisa_kev("https://www.cisa.gov/feeds/kev.json"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cve_id"], "CVE-2023-9999")
        self.assertEqual(items[0]["source"], "CISA KEV")
        self.assertIn("ransomware", items[0]["snippet"].lower())

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_http_error_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(503, text="Service Unavailable"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_cisa_kev("https://www.cisa.gov/feeds/kev.json"))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_network_exception_returns_empty(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=Exception("DNS failure"))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_cisa_kev("https://www.cisa.gov/feeds/kev.json"))
        self.assertEqual(items, [])

    @patch("src.security_digest.fetchers.httpx.AsyncClient")
    def test_entries_without_cve_id_are_skipped(self, mock_client_cls):
        payload = {"vulnerabilities": [{"vendorProject": "Acme", "product": "Widget"}]}
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=_mock_response(200, payload))
        mock_client_cls.return_value = mock_client

        items = _run(fetch_cisa_kev("https://www.cisa.gov/feeds/kev.json"))
        self.assertEqual(items, [])


# ── _infer_ecosystem_from_nvd ──────────────────────────────────────────────────

class InferEcosystemFromNvdTests(unittest.TestCase):
    def test_npm_in_fallback_text(self):
        result = _infer_ecosystem_from_nvd({}, "vulnerability in npm package lodash")
        self.assertEqual(result, "npm")

    def test_pypi_in_fallback_text(self):
        result = _infer_ecosystem_from_nvd({}, "malicious PyPI package uploaded")
        self.assertEqual(result, "PyPI")

    def test_npm_via_cpe_criteria(self):
        vuln = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:npm:npm:*:*:*:*:*:*:*:*", "vulnerable": True}
                            ]
                        }
                    ]
                }
            ]
        }
        result = _infer_ecosystem_from_nvd(vuln, "")
        self.assertEqual(result, "npm")

    def test_unknown_returns_unknown(self):
        result = _infer_ecosystem_from_nvd({}, "Windows kernel exploit")
        self.assertEqual(result, "unknown")


if __name__ == "__main__":
    unittest.main()
