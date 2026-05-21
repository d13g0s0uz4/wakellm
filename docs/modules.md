# Modules

Package and function reference for `src/`.

---

## `src/__main__.py` — Entry point

### `main()`

Public entry point called by `python -m src`. Configures logging then delegates to `_main()`. Catches all unhandled exceptions, logs them at ERROR, and exits with code 1.

### `_main(argv)`

Parses `sys.argv[1:]`. Valid commands:
- `securityDigest` — runs `run_security_digest()` and prints the result to stdout.
- `--help` / `-h` — prints usage and exits 0.
- Anything else — prints usage to stderr and exits 1.

### `_configure_logging()`

Attaches a `logging.StreamHandler` (stderr) to the root logger with `_CloudRunFormatter`. Idempotent — no-ops if handlers are already present.

### `_CloudRunFormatter`

Custom `logging.Formatter` that emits single-line JSON:

```json
{"severity": "INFO", "message": "...", "logger": "src.security_digest.pipeline"}
```

Maps Python log levels to GCP severity strings: `DEBUG → DEBUG`, `INFO → INFO`, `WARNING → WARNING`, `ERROR → ERROR`, `CRITICAL → CRITICAL`.

---

## `src/gemini.py` — GeminiService

### `GeminiService(api_key, model, base_url)`

Wraps `google-genai`'s `genai.Client`. Reads config from `AppEnv` if not passed explicitly.

### `generate_text(prompt, temperature, max_retries, retry_delay_ms) → str`

Plain text generation. Retries up to `max_retries` times with `retry_delay_ms` back-off. Detects spend-cap / quota errors via `is_quota_exhausted_error()` and raises immediately without retrying.

Returns the response text or raises the last exception.

### `generate_json(prompt, schema, temperature, max_retries, retry_delay_ms) → BaseModel | dict`

Structured output generation.

- If `schema` is a `BaseModel` subclass, uses `response_schema=schema` for native structured output (no post-processing).
- Otherwise, calls `generate_text()` and extracts the first JSON block from the response.
- Falls back to `json.loads()` on the full response text if no JSON block is found.
- Validates the result against `schema` and logs a warning on validation errors.

### `is_quota_exhausted_error(exc) → bool`

Returns `True` if the exception message contains quota/spend-cap indicators. Used by `generate_text()` for fail-fast behaviour.

### `_redact(text) → str`

Replaces sequences of 20+ alphanumeric characters in error messages with `[REDACTED]` before logging. Prevents accidental API key exposure in logs.

---

## `src/config/env.py` — AppEnv

`AppEnv(BaseSettings)` loaded via `pydantic-settings`. A singleton is instantiated at module level and imported across the codebase.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `GEMINI_API_KEY` | `SecretStr` | ✓ | — | Redacted in repr |
| `GEMINI_MODEL` | `str` | | `gemini-2.5-flash-lite` | |
| `GEMINI_API_BASE` | `str` | | `https://generativelanguage.googleapis.com/v1beta` | Must be HTTPS + googleapis.com |
| `GITHUB_TOKEN` | `SecretStr` | ✓ | — | |
| `SOURCES_CONFIG` | `str` | | `config/sources.yaml` | Path to feed config file |
| `SECURITY_MONITORED_PACKAGES` | `str` | | `""` | CSV / JSON / newline list |
| `LLM_GLOBAL_CONTEXT` | `str` | | `""` | Injected into every LLM prompt |
| `SECURITY_MAX_TRIAGE_ITEMS` | `int` | | `40` | Intel items passed to LLM for triage |
| `SECURITY_MAX_ALERT_THREATS` | `int` | | `10` | Max threats in final output |

`_validate_gemini_base` validator rejects non-HTTPS or non-googleapis.com values.

---

## `src/config/sources_config.py` — SourcesConfig

Typed loader for `sources.yaml` / `sources.json`.

### `SourcesConfig.load(path) → SourcesConfig`

Reads the file, detects format by extension, and calls `_from_dict()`.

### `SourcesConfig._from_dict(d) → SourcesConfig`

Constructs typed dataclasses from the raw dict. Calls `_parse_rss_feeds()` for the `rss_feeds.feeds` list.

### `_parse_rss_feeds(raw) → list[RssFeedEntry]`

Validates that every RSS feed URL starts with `https://`. Raises `ValueError` otherwise.

### Dataclasses

| Class | Fields |
|---|---|
| `GitHubAdvisoriesConfig` | `enabled`, `ecosystems: list[str]`, `per_page: int` |
| `RedditConfig` | `enabled`, `subreddits: list[str]` |
| `RssFeedEntry` | `url: str` |
| `RssFeedsConfig` | `enabled`, `feeds: list[RssFeedEntry]` |
| `NvdConfig` | `enabled`, `api_url: str` |
| `CisaKevConfig` | `enabled`, `feed_url: str` |

---

## `src/utils/llm_schemas.py` — LLM response models

### `SecurityThreat` (Pydantic BaseModel)

| Field | Type | Description |
|---|---|---|
| `title` | `str` | Short advisory title |
| `ecosystem` | `str` | Package ecosystem (`npm`, `PyPI`, etc.) |
| `threat_level` | `str` | `CRITICAL` / `HIGH` / `MEDIUM` |
| `summary` | `str` | 2–3 sentence description |
| `source_url` | `str` | Canonical URL — validated by `@field_validator` to be blank for non-HTTP(S) values |
| `action_required` | `str` | What to do |
| `cve_id` | `str \| None` | Normalised CVE ID |
| `fixed_version` | `str \| None` | Patched version string |

**`@field_validator("source_url")`** — returns `""` for any value that does not start with `http://` or `https://`. The pipeline's existing `if not source_url: continue` check then skips these threats. This prevents schema-validated threats with fabricated URLs from reaching the output.

### `SecurityTriageResponse` (Pydantic BaseModel)

| Field | Type | Default |
|---|---|---|
| `threats` | `list[SecurityThreat]` | `[]` |

Used as the `response_schema` in `generate_json()`.

### `SocialDrafts` (Pydantic BaseModel)

| Field | Type | Default | Description |
|---|---|---|---|
| `reddit_title` | `str` | `""` | News-style post title |
| `reddit_body` | `str` | `""` | Full Reddit markdown post body |
| `twitter_thread` | `list[str]` | `[]` | Thread tweets, each ≤280 chars |
| `linkedin_post` | `str` | `""` | Professional narrative ≤1100 chars |

Used as the `response_schema` in `run_social_drafts()`.

### `log_validation_rejection(error)`

Logs Pydantic `ValidationError` details as a structured JSON WARNING to stderr. Called when LLM output fails schema validation.

---

## `src/utils/async_utils.py`

### `sleep(ms: int)`

`await sleep(500)` — thin wrapper around `asyncio.sleep` accepting milliseconds.

---

## `src/security_digest/utils.py` — Normalisation helpers

### `_safe_iso_date(value) → str`

Parses any datetime string to UTC ISO-8601. Returns `""` and logs a WARNING on parse failure.

### `_infer_ecosystem(text) → str`

Keyword scan of `text` for ecosystem names. Returns the first match (`npm`, `PyPI`, `Maven`, etc.) or `"supply-chain"` for general security news, or `"unknown"`.

### `_normalize_cve_id(raw) → str`

Upper-cases and strip-normalises a CVE string. Returns `""` for malformed input.

### `_extract_cve_id(text) → str`

Regex scan for `CVE-YYYY-NNNN` pattern in free text. Returns the first match or `""`.

### `_build_dedup_key(threat_dict) → str`

Returns `cve_id` if present, else `source_url`, else `title.lower()[:80]`. Used for deduplication in `_normalize_intel()`.

### `_normalize_optional_text(value) → str | None`

Strips whitespace; returns `None` for empty/None values.

### `_normalize_threat_level(raw) → str`

Maps raw LLM threat level to one of `CRITICAL`, `HIGH`, `MEDIUM`. Defaults to `MEDIUM` for unrecognised values.

---

## `src/security_digest/monitored.py` — Monitored-package matching

### `_parse_monitored_packages(raw) → list[str]`

Accepts any of:
- JSON array string: `'["react","lodash"]'`
- Comma-separated: `"react,lodash,express"`
- Semicolon-separated: `"react;lodash"`
- Newline-separated

Returns a deduplicated, lowercased list.

### `_find_monitored_package_match(threat, packages) → str | None`

Builds word-boundary regex `(^|[^a-z0-9@/_.-]){pkg}($|[^a-z0-9@/_.-])` for each package and searches across `title + summary + action_required + source_url` (all lowercased). Returns the matched package name or `None`.

### `_apply_monitored_priority(threats, raw_monitored) → list[dict]`

Calls `_parse_monitored_packages()`, then **precompiles all regexes once** before the threat loop. For each matched threat, sets:
- `threat_level = "CRITICAL"`
- `priority_tag = "TOP_PRIORITY"`
- `matched_package = <matched_name>`

---

## `src/security_digest/fetchers.py` — 5 async HTTP fetchers

All fetchers use `httpx.AsyncClient` with a 30-second timeout and log failures at WARNING or ERROR level. All return `list[dict[str, str]]`.

### `fetch_github_advisories(ecosystems, per_page) → list[dict]`

Queries the GitHub Advisory Database REST API (`/advisories?ecosystem={e}&per_page={n}`) for each ecosystem in parallel. Extracts `fixed_version` from `vulnerabilities[].first_patched_version.identifier`.

Raises `HTTPStatusError` / `RequestError` on failure; logs at ERROR and returns `[]`.

### `fetch_reddit_json(subreddits) → list[dict]`

Searches each subreddit for `npm OR pypi OR malicious package` via `r/{sub}/search.json?q=...&sort=new&t=day`. Handles `403` gracefully (Reddit blocks bots) — logs WARNING and returns `[]`.

### `fetch_rss_feeds(feed_urls) → list[dict]`

Fetches each RSS/Atom URL and parses with `xml.etree.ElementTree`. Supports `<item>` (RSS 2.0) and `<entry>` (Atom). Logs WARNING on HTTP error or malformed XML; continues with remaining feeds.

### `fetch_nvd_cves(api_url) → list[dict]`

Queries the NIST NVD CVE 2.0 API for CVEs modified in the last 7 days (`lastModStartDate` / `lastModEndDate` params, `resultsPerPage=100`). Uses `_infer_ecosystem_from_nvd()` to set `ecosystem_hint`.

### `fetch_cisa_kev(feed_url) → list[dict]`

Downloads the CISA KEV catalog (JSON). Skips entries without a `cveID` field. Returns a flat list with `threat_level` hint pre-set to `CRITICAL`.

### `_infer_ecosystem_from_nvd(vuln, fallback_text) → str`

Inspects `cpe` criteria strings in the NVD vulnerability object for npm/PyPI indicators. Falls back to `_infer_ecosystem(fallback_text)`.

---

## `src/security_digest/intel.py` — Dedup, prioritisation, enrichment

### Constants

| Name | Value | Description |
|---|---|---|
| `_MAX_TRIAGE_INTEL_ITEMS` | from `env` | Items sent to LLM (default 40) |
| `_MAX_ALERT_THREATS` | from `env` | Max threats in output (default 10) |

### `_normalize_intel(items) → list[dict]`

**Pass 1**: Dedup by `{url}|{title.lower()}`. Drops items with empty URL or title.  
**Pass 2**: For items sharing a `cve_id`, keep only the highest-authority source: CISA KEV (0) > NIST NVD (1) > GitHub Advisory (2) > others (99).

### `_prioritize_intel_for_triage(items) → list[dict]`

Stable sort by `(source_rank, ecosystem_relevance, has_cve, recency)`. Returns top `_MAX_TRIAGE_INTEL_ITEMS`.

### `_fallback_threats_from_intel(items) → list[dict]`

Deterministic extraction: for items with a `cve_id`, synthesises a `SecurityThreat`-shaped dict with `threat_level="HIGH"`. No LLM call. Used when Gemini is unavailable.

### `_select_alert_threats(threats) → list[dict]`

Caps to `_MAX_ALERT_THREATS`. Fill order: `TOP_PRIORITY` → `CRITICAL` → `HIGH` → `MEDIUM`.

### `_enrich_threats(threats, intel) → list[dict]`

Matches each threat's `source_url` against original intel items. Backfills `cve_id`, `fixed_version`, then adds `dedup_key` and `status: "OPEN"`.

---

## `src/security_digest/prompts.py` — LLM prompt

### `get_security_triage_prompt(intel_json, monitored_packages, global_context, max_threats) → str`

Builds the full triage prompt. `max_threats` (default: `env.SECURITY_MAX_ALERT_THREATS`) is injected into rule 4 so the model caps its response. Structure:
1. Role statement + optional `global_context`
2. Threat level rubric (CRITICAL / HIGH / MEDIUM definitions)
3. Rules: discard Windows/WordPress/hardware, focus on npm/PyPI/supply-chain, max `N` threats, no hallucinated URLs, empty → `{"threats": []}`
4. Monitored packages line
5. Raw intel JSON

---

## `src/security_digest/social_prompts.py` — Social drafts prompt

### `get_social_drafts_prompt(threats_json, run_date, max_tweets) → str`

Builds the social formatting prompt. `max_tweets` defaults to 8. The prompt instructs Gemini to produce a single JSON object with four keys (`reddit_title`, `reddit_body`, `twitter_thread`, `linkedin_post`) and enforces per-platform constraints:

| Platform | Constraint |
|---|---|
| Reddit | Full markdown post; source URLs from input verbatim |
| Twitter/X | ≤280 chars per tweet, ≤`max_tweets` total; `[REDDIT_LINK]` placeholder in closing tweet |
| LinkedIn | 900–1100 chars; no raw CVE IDs; hashtags on final line |

---

## `src/security_digest/social_formatter.py` — Social draft generation

### `run_social_drafts(threats, gemini, run_date, max_tweets) → SocialDrafts | None`

Generates social media drafts for all three platforms in a single Gemini call.

- `threats`: the finalised output threat list (dicts, not Pydantic models)
- `gemini`: a `GeminiService` instance (reused from the pipeline run)
- `run_date`: ISO date string used in post headers; defaults to today UTC
- `max_tweets`: passed through to `get_social_drafts_prompt()`

Uses `temperature=0.4` (higher than triage to allow more natural phrasing). Returns `None` and logs an ERROR if generation fails; the pipeline continues and omits the `drafts` key from output.

---

## `src/security_digest/pipeline.py` — Orchestration

### `run_security_digest(*, social) → None`

Main entry point. `social=True` when `--social` flag is passed. Steps:

1. Load `AppEnv` and `SourcesConfig`
2. `asyncio.gather()` all five fetch coroutines
3. Log fetch counts: `[fetch] github=N reddit=N rss=N nvd=N cisa=N`
4. `_normalize_intel()` → `_prioritize_intel_for_triage()`
5. Build `intel_url_set` and `intel_by_cve` lookup tables
6. Call `GeminiService.generate_json(prompt, SecurityTriageResponse)`; on failure fall back to `_fallback_threats_from_intel()`
7. Hallucination guard: check each `source_url`; recover via CVE lookup or drop + log WARNING
8. `_enrich_threats()` → `_apply_monitored_priority()` → `_select_alert_threats()`
9. If `social=True`: call `run_social_drafts()`; merge result into output envelope as `drafts`
10. `print(json.dumps(output, indent=2))`
9. Return `{"run_at": "<iso>", "threats": [...]}` — caller prints JSON to stdout
