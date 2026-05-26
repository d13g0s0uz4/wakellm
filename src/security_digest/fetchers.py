from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import quote_plus
from xml.etree import ElementTree

import httpx

from src.config.env import env
from src.security_digest.utils import (
    _infer_ecosystem,
    _safe_iso_date,
    _normalize_cve_id,
    _extract_cve_id,
)

_log = logging.getLogger(__name__)
_ATOM_NS = "http://www.w3.org/2005/Atom"


async def fetch_github_advisories(
    ecosystems: list[str],
    per_page: int = 50,
    lookback_hours: int = 24,
) -> list[dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {env.GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "wakellm-security",
    }

    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    async with httpx.AsyncClient(timeout=15.0) as client:
        responses = await asyncio.gather(
            *[
                client.get(
                    "https://api.github.com/advisories",
                params={"ecosystem": eco, "per_page": str(per_page), "sort": "published", "direction": "desc"},
                    headers=headers,
                )
                for eco in ecosystems
            ],
            return_exceptions=True,
        )

    items: list[dict[str, str]] = []
    for resp in responses:
        if isinstance(resp, Exception):
            _log.error("GitHub advisory fetch failed: %s", resp)
            continue
        if resp.status_code >= 400:
            _log.error("GitHub advisory fetch failed (%d): %s", resp.status_code, resp.text[:300])
            continue

        data = resp.json() if resp.text else []
        if not isinstance(data, list):
            continue

        for advisory in data:
            if not isinstance(advisory, dict):
                continue
            summary = str(advisory.get("summary") or "GitHub advisory")
            description = str(advisory.get("description") or "")
            vulnerabilities = advisory.get("vulnerabilities") if isinstance(advisory.get("vulnerabilities"), list) else []
            fixed_version = None
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                first_patched = vulnerability.get("first_patched_version")
                if isinstance(first_patched, dict):
                    identifier = first_patched.get("identifier")
                    if isinstance(identifier, str) and identifier.strip():
                        fixed_version = identifier.strip()
                        break
            item = {
                "title": summary,
                "source": "GitHub Advisory",
                "url": str(advisory.get("html_url") or ""),
                "snippet": description[:500],
                "ecosystem_hint": _infer_ecosystem(f"{summary} {description}"),
                "published_at": _safe_iso_date(advisory.get("published_at") if isinstance(advisory.get("published_at"), str) else None),
                "cve_id": _extract_cve_id(
                    str(advisory.get("cve_id") or ""),
                    summary,
                    description,
                ) or "",
                "fixed_version": fixed_version or "",
            }
            try:
                pub_dt = datetime.fromisoformat(item["published_at"])
                if pub_dt < cutoff:
                    continue
            except Exception:
                pass
            items.append(item)

    return items


async def fetch_reddit_json(subreddits: list[str]) -> list[dict[str, str]]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "wakellm-security/0.1 (+https://github.com)",
    }

    query = quote_plus("npm OR pypi OR malicious package")
    urls = [
        f"https://www.reddit.com/r/{sub}/search.json?q={query}&sort=new&t=day&restrict_sr=1&limit=25&raw_json=1"
        for sub in subreddits
    ]

    async with httpx.AsyncClient(timeout=15.0) as client:
        responses = await asyncio.gather(
            *[client.get(url, headers=headers) for url in urls],
            return_exceptions=True,
        )

    items: list[dict[str, str]] = []
    saw_forbidden = False
    for resp in responses:
        if isinstance(resp, Exception):
            message = str(resp)
            if "403" in message:
                saw_forbidden = True
                continue
            _log.warning("Reddit fetch failed: %s", resp)
            continue
        if resp.status_code >= 400:
            if resp.status_code == 403:
                saw_forbidden = True
                continue
            _log.warning("Reddit fetch failed (%d) for endpoint %s", resp.status_code, resp.url)
            continue

        data: Any = resp.json() if resp.text else {}
        children = data.get("data", {}).get("children", []) if isinstance(data, dict) else []
        if not isinstance(children, list):
            continue

        for child in children:
            post = child.get("data", {}) if isinstance(child, dict) else {}
            title = str(post.get("title") or "")
            if not title:
                continue
            selftext = str(post.get("selftext") or "")
            permalink = str(post.get("permalink") or "")
            item = {
                "title": title,
                "source": f"Reddit r/{str(post.get('subreddit') or 'unknown')}",
                "url": str(post.get("url") or (f"https://www.reddit.com{permalink}" if permalink else "")),
                "snippet": selftext[:500],
                "ecosystem_hint": _infer_ecosystem(f"{title} {selftext}"),
                "published_at": datetime.fromtimestamp(float(post.get("created_utc") or datetime.now(timezone.utc).timestamp()), timezone.utc).isoformat(),
                "cve_id": _extract_cve_id(title, selftext) or "",
                "fixed_version": "",
            }
            items.append(item)

    if saw_forbidden:
        _log.warning("Reddit fetch blocked with 403; skipping Reddit source for this run.")

    return items


async def fetch_rss_feeds(feed_urls: list[str]) -> list[dict[str, str]]:
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        responses = await asyncio.gather(
            *[client.get(url, headers={"User-Agent": "wakellm-security/0.1"}) for url in feed_urls],
            return_exceptions=True,
        )

    items: list[dict[str, str]] = []
    for source_url, resp in zip(feed_urls, responses):
        if isinstance(resp, Exception):
            _log.warning("RSS fetch failed (%s): %s", source_url, resp)
            continue
        if resp.status_code >= 400:
            _log.warning("RSS fetch failed (%s, %d)", source_url, resp.status_code)
            continue

        if not resp.text.strip():
            _log.warning("RSS fetch failed (%s): empty response body", source_url)
            continue

        try:
            root = ElementTree.fromstring(resp.text)
        except Exception as exc:
            _log.warning("RSS parse failed (%s): %s", source_url, exc)
            continue

        _ns = f"{{{_ATOM_NS}}}"
        rss_nodes = root.findall(".//item")
        atom_nodes = root.findall(f".//{_ns}entry") if not rss_nodes else []

        for node in rss_nodes:
            title = (node.findtext("title") or "").strip()
            link = (node.findtext("link") or "").strip()
            description = (node.findtext("description") or "").strip()
            pub_date = (node.findtext("pubDate") or "").strip()
            if not title or not link:
                continue
            items.append(
                {
                    "title": title,
                    "source": source_url,
                    "url": link,
                    "snippet": description[:500],
                    "ecosystem_hint": _infer_ecosystem(f"{title} {description}"),
                    "published_at": _safe_iso_date(pub_date),
                    "cve_id": _extract_cve_id(title, description) or "",
                    "fixed_version": "",
                }
            )

        for node in atom_nodes:
            title = (node.findtext(f"{_ns}title") or "").strip()
            link_el = node.find(f"{_ns}link[@rel='alternate']") or node.find(f"{_ns}link")
            link = (link_el.get("href") if link_el is not None else "").strip()
            description = (node.findtext(f"{_ns}summary") or node.findtext(f"{_ns}content") or "").strip()
            pub_date = (node.findtext(f"{_ns}published") or node.findtext(f"{_ns}updated") or "").strip()
            if not title or not link:
                continue
            items.append(
                {
                    "title": title,
                    "source": source_url,
                    "url": link,
                    "snippet": description[:500],
                    "ecosystem_hint": _infer_ecosystem(f"{title} {description}"),
                    "published_at": _safe_iso_date(pub_date),
                    "cve_id": _extract_cve_id(title, description) or "",
                    "fixed_version": "",
                }
            )

    return items


def _infer_ecosystem_from_nvd(vuln: dict[str, Any], fallback_text: str) -> str:
    text = fallback_text.lower()
    if "pypi" in text or "pip" in text:
        return "PyPI"
    if "npm" in text or "node" in text:
        return "npm"

    configurations = vuln.get("configurations")
    if not isinstance(configurations, list):
        return "unknown"

    for cfg in configurations:
        if not isinstance(cfg, dict):
            continue
        nodes = cfg.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if not isinstance(match, dict):
                    continue
                criteria = str(match.get("criteria") or "").lower()
                if "npm" in criteria or ":node.js:" in criteria or ":nodejs:" in criteria:
                    return "npm"
                if "pypi" in criteria or ":python:" in criteria or ":python3:" in criteria:
                    return "PyPI"

    return "unknown"


async def fetch_nvd_cves(api_url: str) -> list[dict[str, str]]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    params = {
        "resultsPerPage": "100",
        "startIndex": "0",
        "lastModStartDate": start.isoformat().replace("+00:00", "Z"),
        "lastModEndDate": now.isoformat().replace("+00:00", "Z"),
    }

    headers = {
        "Accept": "application/json",
        "User-Agent": "wakellm-security/0.1",
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            resp = await client.get(api_url, params=params, headers=headers)
        except Exception as exc:
            _log.error("NVD fetch failed: %s", exc)
            return []

    if resp.status_code >= 400:
        _log.error("NVD fetch failed (%d): %s", resp.status_code, resp.text[:300])
        return []

    payload: Any = resp.json() if resp.text else {}
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    if not isinstance(vulnerabilities, list):
        return []

    items: list[dict[str, str]] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        if not isinstance(cve, dict):
            continue

        cve_id = _normalize_cve_id(str(cve.get("id") or ""))
        if not cve_id:
            continue

        descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
        description = ""
        for desc in descriptions:
            if not isinstance(desc, dict):
                continue
            if str(desc.get("lang") or "").lower() == "en":
                description = str(desc.get("value") or "").strip()
                break
        if not description and descriptions:
            first_desc = descriptions[0]
            if isinstance(first_desc, dict):
                description = str(first_desc.get("value") or "").strip()

        title = f"{cve_id}"
        if description:
            title = f"{cve_id} - {description[:120]}"

        ecosystem = _infer_ecosystem_from_nvd(cve, f"{title} {description}")
        published = _safe_iso_date(str(cve.get("published") or ""))

        # Discard NVD entries with no developer-relevant keywords.
        if not any(kw in f"{title} {description}".lower() for kw in _DEV_RELEVANCE_KEYWORDS):
            continue

        items.append(
            {
                "title": title,
                "source": "NIST NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "snippet": description[:500],
                "ecosystem_hint": ecosystem,
                "published_at": published,
                "cve_id": cve_id,
                "fixed_version": "",
            }
        )

    return items


# Keywords indicating relevance to developer supply-chain security.
# Applied to both NVD and CISA KEV entries before triage.
_DEV_RELEVANCE_KEYWORDS: frozenset[str] = frozenset([
    "npm", "node", "javascript", "typescript",
    "pypi", "python", "pip",
    "rubygems", "ruby", "gem",
    "maven", "gradle", "java", "spring",
    "nuget", ".net", "dotnet",
    "cargo", "rust",
    "go module", "golang",
    "github action", "github actions", "workflow",
    "ci/cd", "jenkins", "circleci", "gitlab",
    "docker", "container", "kubernetes", "helm",
    "terraform", "ansible",
    "supply chain", "supply-chain",
    "malicious package", "typosquat",
    "package manager", "package registry",
    "open source", "open-source",
    "dependency", "library",
    "langchain", "litellm", "ollama", "langflow", "huggingface",
    "trivy", "snyk", "sonarqube",
])


async def fetch_cisa_kev(feed_url: str) -> list[dict[str, str]]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "wakellm-security/0.1",
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            resp = await client.get(feed_url, headers=headers)
        except Exception as exc:
            _log.error("CISA KEV fetch failed: %s", exc)
            return []

    if resp.status_code >= 400:
        _log.error("CISA KEV fetch failed (%d): %s", resp.status_code, resp.text[:300])
        return []

    payload: Any = resp.json() if resp.text else {}
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    if not isinstance(vulnerabilities, list):
        return []

    items: list[dict[str, str]] = []
    kev_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue

        cve_id = _normalize_cve_id(str(vulnerability.get("cveID") or ""))
        if not cve_id:
            continue

        date_added_raw = str(vulnerability.get("dateAdded") or "")
        try:
            date_added_dt = datetime.fromisoformat(_safe_iso_date(date_added_raw))
            if date_added_dt < kev_cutoff:
                continue
        except Exception:
            pass  # keep if date unparseable

        vendor = str(vulnerability.get("vendorProject") or "").strip()
        product = str(vulnerability.get("product") or "").strip()
        name = str(vulnerability.get("vulnerabilityName") or "").strip()
        short_description = str(vulnerability.get("shortDescription") or "").strip()
        ransomware = str(vulnerability.get("knownRansomwareCampaignUse") or "").strip()

        title_parts = [cve_id]
        if name:
            title_parts.append(name)
        title = " - ".join(title_parts)

        snippet_parts = [part for part in [vendor, product, short_description] if part]
        snippet = ". ".join(snippet_parts)
        if ransomware:
            snippet = f"{snippet}. Known ransomware campaign use: {ransomware}." if snippet else f"Known ransomware campaign use: {ransomware}."

        ecosystem_hint = _infer_ecosystem(f"{title} {snippet}")

        # Discard entries with no developer-relevant keywords.
        combined_lower = f"{title} {snippet}".lower()
        if not any(kw in combined_lower for kw in _DEV_RELEVANCE_KEYWORDS):
            continue

        items.append(
            {
                "title": title,
                "source": "CISA KEV",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "snippet": snippet[:500],
                "ecosystem_hint": ecosystem_hint,
                "published_at": _safe_iso_date(str(vulnerability.get("dateAdded") or "")),
                "cve_id": cve_id,
                "fixed_version": "",
            }
        )

    return items
