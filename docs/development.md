# Development

## Prerequisites

- Python 3.12+
- A `.env` file with at least `GEMINI_API_KEY` and `GITHUB_TOKEN`

## Setup

```bash
# Clone and enter the repo
git clone https://github.com/yourorg/wakellm-security
cd wakellm-security

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # macOS / Linux

# Install runtime + dev dependencies
pip install -r requirements-dev.txt

# Copy and fill in the env file
cp .env.example .env
# Edit .env: set GEMINI_API_KEY and GITHUB_TOKEN at minimum
```

## Running locally

```bash
# Run the full pipeline — JSON to stdout, diagnostics to stderr
python -m src securityDigest

# Show CLI help
python -m src --help
```

To point at a custom sources file:

```bash
SOURCES_CONFIG=config/sources-minimal.yaml python -m src securityDigest
```

To test monitored-package escalation:

```bash
SECURITY_MONITORED_PACKAGES="react,lodash,express" python -m src securityDigest
```

## Running tests

```bash
pytest tests/python/ -v
```

### Test layout

| File | What it covers |
|---|---|
| `tests/python/test_security_digest.py` | `_parse_monitored_packages`, `_find_monitored_package_match`, `_apply_monitored_priority`, `_build_dedup_key`, `_normalize_threat_level`, `_prioritize_intel_for_triage`, `_fallback_threats_from_intel`, `_select_alert_threats` |
| `tests/python/test_fetchers.py` | All 5 fetch functions + `_infer_ecosystem_from_nvd` — mocked with `unittest.mock` |
| `tests/python/test_gemini_json_parsing.py` | `_extract_json_payload` edge cases |
| `tests/python/test_gemini_service_fallback.py` | Retry logic, quota errors, search-mode fallback |

Tests require no network access — all HTTP calls are mocked. The test files set `GEMINI_API_KEY` and `GITHUB_TOKEN` via `os.environ.setdefault` before importing project modules.

### Running tests in Docker

```bash
docker build --target dev -t wakellm-security:dev .
docker run --rm wakellm-security:dev pytest tests/python/ -v
```

## Project layout

```
.
├── Dockerfile
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── wakellm.sh              # Deploy / run management script
├── .env.example
├── config/
│   └── sources.yaml        # Default feed configuration
├── docs/                   # This documentation
├── src/
│   ├── __init__.py
│   ├── __main__.py         # Entry point: python -m src securityDigest
│   ├── gemini.py           # GeminiService — generate_text / generate_json
│   ├── config/
│   │   ├── env.py          # AppEnv (pydantic-settings)
│   │   └── sources_config.py
│   ├── security_digest/
│   │   ├── __init__.py     # Re-exports for test compatibility
│   │   ├── utils.py        # CVE regex, text normalisation helpers
│   │   ├── monitored.py    # Monitored-package matching + escalation
│   │   ├── fetchers.py     # 5 async HTTP fetchers
│   │   ├── intel.py        # Dedup, prioritisation, fallback, enrichment
│   │   ├── prompts.py      # LLM prompt builder
│   │   └── pipeline.py     # run_security_digest() orchestration
│   └── utils/
│       ├── llm_schemas.py  # Pydantic v2 models for LLM responses
│       └── async_utils.py  # sleep() helper
└── tests/
    └── python/
        ├── __init__.py
        ├── test_security_digest.py
        ├── test_fetchers.py
        ├── test_gemini_json_parsing.py
        └── test_gemini_service_fallback.py
```

## Logging

All diagnostic output goes to **stderr** as structured JSON, consumed by Cloud Run's logging agent. In local development the same JSON lines are printed to your terminal. The format is:

```json
{"severity": "INFO", "message": "[fetch] github=12 reddit=3 rss=8 nvd=47 cisa=5", "logger": "src.security_digest.pipeline"}
```

Severity levels used:
- `INFO` — normal pipeline milestones (start, fetch counts, fallback notice)
- `WARNING` — recoverable issues (date parse failure, Reddit 403, dropped hallucinated URL)
- `ERROR` — unrecoverable fetch failures (NVD/CISA/GitHub HTTP errors, Gemini quota exhausted)

## Adding a new feed source

1. Add the fetcher coroutine to `src/security_digest/fetchers.py`. Return `list[dict[str, str]]` matching the standard schema (`title`, `source`, `url`, `snippet`, `ecosystem_hint`, `published_at`, `cve_id`, `fixed_version`).
2. Add a config dataclass to `src/config/sources_config.py` and wire it up in `_from_dict()`.
3. Add the corresponding section to `config/sources.yaml`.
4. Add the fetch task to `pipeline.py`'s `fetch_tasks` list and destructure the result.
5. Add tests in `tests/python/test_fetchers.py` with mocked httpx responses.
