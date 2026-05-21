# Configuration

## Environment variables

All variables are loaded by `src/config/env.py` via `pydantic-settings`. They can be set in a `.env` file (for local development) or injected by Cloud Run from GCP Secret Manager (for production).

### Required

| Variable | Description |
|---|---|
| `GEMINI_API_KEY` | Google AI API key. [Get one](https://aistudio.google.com/). |
| `GITHUB_TOKEN` | GitHub personal access token. Needs no special scopes — public advisory read is unauthenticated but the token raises the rate limit significantly. |

### Optional

| Variable | Default | Description |
|---|---|---|
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model name. |
| `GEMINI_API_BASE` | `https://generativelanguage.googleapis.com/v1beta` | Base URL for the Gemini API. Must be an `https://` URL ending in `googleapis.com`. |
| `SOURCES_CONFIG` | `config/sources.yaml` | Path to the feed configuration file (YAML or JSON). Relative to the working directory. |
| `SECURITY_MONITORED_PACKAGES` | _(empty)_ | Comma, semicolon, or newline-separated list of internal dependency names to watch. Threats mentioning these packages are auto-escalated to `CRITICAL` + `TOP_PRIORITY`. Accepts JSON array format too: `["react","lodash"]`. |
| `LLM_GLOBAL_CONTEXT` | _(empty)_ | Free-text string injected after the role statement in every LLM prompt. Use to provide project-specific context (e.g. `"We run a Node.js monorepo with React and Express."`). |
| `NODE_ENV` | `development` | Passed to the Cloud Run Job as an env var. Set to `production` in prod deployments. |

### GCP Secret Manager (production)

In production, `wakellm.sh --deploy` maps the following secrets automatically:

| Secret name | Env var |
|---|---|
| `gemini-api-key` | `GEMINI_API_KEY` |
| `github-token` | `GITHUB_TOKEN` |
| `SECURITY_MONITORED_PACKAGES` _(optional)_ | `SECURITY_MONITORED_PACKAGES` |
| `LLM_GLOBAL_CONTEXT` _(optional)_ | `LLM_GLOBAL_CONTEXT` |

The two optional secrets are only mounted if they already exist in Secret Manager — `wakellm.sh` checks with `gcloud secrets describe` before adding them to the `--set-secrets` flag.

Create secrets:

```bash
echo -n "your-api-key" | gcloud secrets create gemini-api-key \
  --project=YOUR_PROJECT \
  --replication-policy=automatic \
  --data-file=-

echo -n "ghp_xxxx" | gcloud secrets create github-token \
  --project=YOUR_PROJECT \
  --replication-policy=automatic \
  --data-file=-

# Optional:
echo -n "react,lodash,express" | gcloud secrets create SECURITY_MONITORED_PACKAGES \
  --project=YOUR_PROJECT \
  --replication-policy=automatic \
  --data-file=-
```

---

## sources.yaml reference

`config/sources.yaml` controls which threat intelligence feeds are fetched each run. All top-level sections are optional; set `enabled: false` to skip a source without removing its config.

### Default file

```yaml
github_advisories:
  enabled: true
  ecosystems:
    - npm
    - pip
  per_page: 50

reddit:
  enabled: true
  subreddits:
    - netsec
    - cybersecurity

rss_feeds:
  enabled: true
  feeds:
    - url: https://phylum.io/blog/rss/
    - url: https://snyk.io/blog/feed/
    - url: https://www.bleepingcomputer.com/feed/

nvd:
  enabled: true
  api_url: https://services.nvd.nist.gov/rest/json/cves/2.0

cisa_kev:
  enabled: true
  feed_url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### Field reference

#### `github_advisories`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Fetch GitHub Advisory Database. |
| `ecosystems` | list[str] | `["npm","pip"]` | Ecosystems to query. Valid values: `npm`, `pip`, `rubygems`, `maven`, `nuget`, `composer`, `go`, `rust`, `erlang`, `actions`. Each ecosystem is fetched as a separate parallel request. |
| `per_page` | int | `50` | Results per ecosystem request (max 100). |

#### `reddit`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Fetch Reddit. |
| `subreddits` | list[str] | `["netsec","cybersecurity"]` | Subreddits to search. Each is queried for `npm OR pypi OR malicious package` posted in the last 24 hours. |

#### `rss_feeds`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Fetch RSS feeds. |
| `feeds` | list[{url}] | see default | List of feed objects. Each must have a `url` field. **URLs must use `https://`** — a `ValueError` is raised at startup for any non-HTTPS URL. |

#### `nvd`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Fetch NIST NVD CVE 2.0 API. |
| `api_url` | str | NVD endpoint | CVE API base URL. Fetches CVEs modified in the last 7 days, `resultsPerPage=100`. |

#### `cisa_kev`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Fetch CISA Known Exploited Vulnerabilities catalog. |
| `feed_url` | str | CISA endpoint | Full URL to the KEV JSON catalog. |

### Using a custom sources file

Point to a different file via env var:

```bash
SOURCES_CONFIG=config/sources-minimal.yaml python -m src securityDigest
```

The file can be YAML (`.yaml`/`.yml`) or JSON (`.json`).
