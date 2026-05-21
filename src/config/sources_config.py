from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RssFeedEntry:
    url: str


@dataclass
class GitHubAdvisoriesConfig:
    enabled: bool = True
    ecosystems: list[str] = field(default_factory=lambda: ["npm", "pip"])
    per_page: int = 50


@dataclass
class RedditConfig:
    enabled: bool = True
    subreddits: list[str] = field(default_factory=lambda: ["netsec", "cybersecurity"])


@dataclass
class RssFeedsConfig:
    enabled: bool = True
    feeds: list[RssFeedEntry] = field(default_factory=list)


@dataclass
class NvdConfig:
    enabled: bool = True
    api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CisaKevConfig:
    enabled: bool = True
    feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_rss_feeds(raw: list[Any]) -> list[RssFeedEntry]:
    """Parse and validate RSS feed entries, requiring HTTPS URLs."""
    feeds: list[RssFeedEntry] = []
    for f in raw:
        if not isinstance(f, dict) or not f.get("url"):
            continue
        url = str(f["url"])
        if not url.startswith("https://"):
            raise ValueError(f"RSS feed URL must use HTTPS, got: {url!r}")
        feeds.append(RssFeedEntry(url=url))
    return feeds


@dataclass
class SourcesConfig:
    github_advisories: GitHubAdvisoriesConfig = field(default_factory=GitHubAdvisoriesConfig)
    reddit: RedditConfig = field(default_factory=RedditConfig)
    rss_feeds: RssFeedsConfig = field(default_factory=RssFeedsConfig)
    nvd: NvdConfig = field(default_factory=NvdConfig)
    cisa_kev: CisaKevConfig = field(default_factory=CisaKevConfig)

    @classmethod
    def load(cls, path: str) -> "SourcesConfig":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Sources config not found: {path}")

        raw: dict[str, Any]
        if p.suffix in {".yaml", ".yml"}:
            import yaml  # type: ignore[import-untyped]
            with p.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        else:
            with p.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)

        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "SourcesConfig":
        gh_raw = d.get("github_advisories") or {}
        reddit_raw = d.get("reddit") or {}
        rss_raw = d.get("rss_feeds") or {}
        nvd_raw = d.get("nvd") or {}
        kev_raw = d.get("cisa_kev") or {}

        return cls(
            github_advisories=GitHubAdvisoriesConfig(
                enabled=bool(gh_raw.get("enabled", True)),
                ecosystems=list(gh_raw.get("ecosystems") or ["npm", "pip"]),
                per_page=int(gh_raw.get("per_page", 50)),
            ),
            reddit=RedditConfig(
                enabled=bool(reddit_raw.get("enabled", True)),
                subreddits=list(reddit_raw.get("subreddits") or ["netsec", "cybersecurity"]),
            ),
            rss_feeds=RssFeedsConfig(
                enabled=bool(rss_raw.get("enabled", True)),
                feeds=_parse_rss_feeds(rss_raw.get("feeds") or []),
            ),
            nvd=NvdConfig(
                enabled=bool(nvd_raw.get("enabled", True)),
                api_url=str(nvd_raw.get("api_url") or "https://services.nvd.nist.gov/rest/json/cves/2.0"),
            ),
            cisa_kev=CisaKevConfig(
                enabled=bool(kev_raw.get("enabled", True)),
                feed_url=str(kev_raw.get("feed_url") or "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
            ),
        )
