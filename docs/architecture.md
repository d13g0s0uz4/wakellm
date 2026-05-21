# Architecture

## Overview

`wakellm-security` is a stateless Cloud Run Job written in Python 3.12. It runs on demand or on a schedule, collects threat intelligence from five external sources, triages the results with Gemini, and writes a JSON document to stdout. With `--social`, a second Gemini call formats the same threats into Reddit, Twitter/X, and LinkedIn drafts, saved locally by `wakellm.sh`. There is no database, no persistent state, and no inbound HTTP surface.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Cloud Run Job                            │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐      │
│  │ GitHub   │   │ Reddit   │   │   RSS    │   │   NVD    │      │
│  │Advisory  │   │ JSON API │   │  Feeds   │   │  API v2  │      │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘      │
│       │              │              │              │            │
│       └──────────────┴──────────────┴──────────────┘            │
│                       asyncio.gather()                          │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │ CISA KEV fetch  │                          │
│                    └────────┬────────┘                          │
│                             │                                   │
│                   ┌─────────▼──────────┐                        │
│                   │  _normalize_intel  │  dedup: url|title      │
│                   │  (CVE-based dedup) │  then CVE-id pass      │
│                   └─────────┬──────────┘                        │
│                             │                                   │
│                  ┌──────────▼───────────┐                       │
│                  │ _prioritize_intel    │  CISA>NVD>GitHub>RSS  │
│                  │ (top 120 items)      │  + ecosystem + CVE    │
│                  └──────────┬───────────┘                       │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │  Gemini triage  │  structured output       │
│                    │  (temp 0.1)     │  SecurityTriageResponse  │
│                    └────────┬────────┘                          │
│                             │ (fallback: CVE deterministic)     │
│                  ┌──────────▼───────────┐                       │
│                  │  URL hallucination   │  drop unrecoverable   │
│                  │  guard               │  recover via CVE ID   │
│                  └──────────┬───────────┘                       │
│                             │                                   │
│                   ┌─────────▼──────────┐                        │
│                   │  _enrich_threats   │  backfill cve_id,      │
│                   │                    │  fixed_version, status │
│                   └─────────┬──────────┘                        │
│                             │                                   │
│               ┌─────────────▼────────────┐                      │
│               │ _apply_monitored_priority│  escalate matched    │
│               │                          │  packages → CRITICAL │
│               └─────────────┬────────────┘                      │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │   JSON stdout   │  {run_at, threats}       │
│                    └────────┬────────┘                          │
│                             │                                   │
│                    (--social flag only)                         │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │  Social drafts  │  temp 0.4, one call      │
│                    │  Gemini call    │  SocialDrafts schema     │
│                    └────────┬────────┘                          │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │  JSON stdout    │  {run_at, threats,       │
│                    │  (with drafts)  │   drafts:{reddit,x,li}}  │
│                    └─────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

## Data flow

### 1. Parallel fetch

All five fetch coroutines run concurrently via `asyncio.gather()`. Each returns `list[dict[str, str]]` with a uniform schema:

| Field | Description |
|---|---|
| `title` | Advisory or post title |
| `source` | `"GitHub Advisory"` / `"NIST NVD"` / `"CISA KEV"` / `"Reddit r/…"` / feed URL |
| `url` | Canonical URL — validated to be the only source of truth for threats |
| `snippet` | Description body, truncated to 500 chars |
| `ecosystem_hint` | `"npm"` / `"PyPI"` / `"supply-chain"` / `"unknown"` |
| `published_at` | UTC ISO-8601 string |
| `cve_id` | Normalised `CVE-YYYY-NNNN` or `""` |
| `fixed_version` | Patched version string or `""` |

### 2. Normalisation and deduplication

`_normalize_intel()` performs two deduplication passes:

1. **URL + title pass** — primary key `{url}|{title.lower()}`. Drops items with missing URL or title.
2. **CVE-ID pass** — for items that share a `cve_id`, only the highest-authority source is kept: CISA KEV (0) > NIST NVD (1) > GitHub Advisory (2) > all others (99).

### 3. Prioritisation

`_prioritize_intel_for_triage()` sorts by `(source_rank, ecosystem+cve_priority, recency)` and truncates to the top 120 items sent to Gemini. This keeps the prompt focused on actionable supply-chain threats and avoids token bloat.

### 4. LLM triage

A slim payload `{title, url, body, cve_id}` per item is sent to Gemini with `response_schema=SecurityTriageResponse` for native structured output. Temperature is fixed at 0.1. The prompt instructs the model to:
- Discard Windows, WordPress, and hardware CVEs
- Focus on npm, PyPI, and supply-chain threats
- Return CRITICAL / HIGH / MEDIUM threat levels per rubric
- Never construct or guess URLs

If the Gemini call fails, `_fallback_threats_from_intel()` extracts CVE-based threats deterministically from the prioritised intel without LLM involvement.

### 5. Hallucination guard

Every `source_url` in the LLM response is checked against `intel_url_set` (the set of URLs actually fetched). If a URL is not present:
- Recovery is attempted via `intel_by_cve` (CVE ID → canonical URL lookup).
- If recovery succeeds, the hallucinated URL is silently replaced.
- If recovery fails, the threat is **dropped entirely** and logged at WARNING level.

### 6. Enrichment and monitored-package escalation

`_enrich_threats()` backfills `cve_id`, `fixed_version`, `dedup_key`, and `status: "OPEN"` from original intel items matched by URL.

`_apply_monitored_priority()` checks each threat's text against the `SECURITY_MONITORED_PACKAGES` list. Matches are escalated to `threat_level: "CRITICAL"` and tagged `priority_tag: "TOP_PRIORITY"`.

### 7. Output

When run without `--social`:

```json
{
  "run_at": "2026-05-21T10:00:00+00:00",
  "threats": [
    {
      "title": "Malicious package 'lodash-utils' on npm",
      "ecosystem": "npm",
      "threat_level": "CRITICAL",
      "summary": "...",
      "source_url": "https://github.com/advisories/GHSA-...",
      "action_required": "...",
      "cve_id": "CVE-2024-1234",
      "fixed_version": "4.17.22",
      "dedup_key": "CVE-2024-1234",
      "status": "OPEN",
      "matched_package": "lodash-utils",
      "priority_tag": "TOP_PRIORITY"
    }
  ]
}
```

`matched_package` and `priority_tag` are omitted when empty (i.e. no monitored-package match).

### 8. Social drafts (optional)

When `--social` is passed, a second Gemini call runs after the threats are finalised. It receives the output threats as input and produces one JSON object with drafts for three platforms:

```json
{
  "run_at": "...",
  "threats": [...],
  "drafts": {
    "reddit_title": "3 npm/supply-chain threats this week: CVE-2025-30066, LiteLLM SQLi, ...",
    "reddit_body": "## Weekly Security Digest — May 22, 2026\n\n...",
    "twitter_thread": [
      "3 npm/supply-chain threats this week. Thread #infosec #supplychain",
      "HIGH: CVE-2025-30066 — tj-actions/changed-files CI/CD GitHub Action compromise. Secrets exposed in workflow logs.",
      "Full report: [REDDIT_LINK] #npm #PyPI #infosec"
    ],
    "linkedin_post": "This week's supply-chain digest..."
  }
}
```

`[REDDIT_LINK]` is a literal placeholder. Replace it manually after posting the Reddit thread.

`wakellm.sh --run --social` fetches the stdout log after the job completes, reconstructs the JSON, and writes a ready-to-paste `./drafts/YYYY-MM-DD-HHmm.md` file locally.

## Package layout

```
src/
├── __init__.py
├── __main__.py             # CLI entry point, logging setup
├── gemini.py               # GeminiService wrapper (generate_text, generate_json)
├── config/
│   ├── env.py              # AppEnv(BaseSettings) — all env vars
│   └── sources_config.py   # SourcesConfig — typed YAML/JSON loader
├── security_digest/
│   ├── __init__.py         # Re-exports public API
│   ├── utils.py            # CVE regex, ecosystem inference, date/text normalisation
│   ├── monitored.py        # Monitored-package parsing, matching, escalation
│   ├── fetchers.py         # 5 async HTTP fetch functions
│   ├── intel.py            # Dedup, prioritisation, fallback, enrichment
│   ├── prompts.py          # get_security_triage_prompt()
│   ├── social_prompts.py   # get_social_drafts_prompt()
│   ├── social_formatter.py # run_social_drafts() — social media draft generation
│   └── pipeline.py         # run_security_digest() — main orchestration
└── utils/
    ├── llm_schemas.py      # SecurityThreat, SecurityTriageResponse, SocialDrafts (Pydantic v2)
    └── async_utils.py      # sleep() helper
```

## Key design decisions

| Decision | Rationale |
|---|---|
| JSON to stdout | Composable with any downstream processor; Cloud Run captures stdout logs |
| Structured output via `response_schema` | More reliable than parsing markdown-wrapped JSON; avoids post-processing |
| Deterministic CVE fallback | Ensures a non-empty report even when Gemini is unavailable or quota-exhausted |
| Hallucinated URL dropping | Fabricated URLs must never appear in security output; safe fail over silent pass-through |
| Two-pass CVE dedup | Same CVE from NVD + GitHub would otherwise double triage cost and confuse the LLM |
| Stateless job | No database means zero operational overhead; idempotent re-runs are safe |
| Alpine base image | Minimal attack surface; `ca-certificates` added explicitly for TLS |
| Non-root container user | Least-privilege; defence-in-depth for container escape scenarios |
| Social drafts as optional second call | Keeps the core digest fast and cheap; social formatting only runs when explicitly requested |
| `[REDDIT_LINK]` placeholder | Reddit URL does not exist when drafts are generated; placeholder prevents broken links |
