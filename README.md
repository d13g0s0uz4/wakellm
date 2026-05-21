# wakellm-security

Cloud Run Job that collects supply-chain threat intelligence, triages it with Gemini, and emits a JSON report to stdout.

**Sources:** GitHub Advisory Database · Reddit (r/netsec, r/cybersecurity) · RSS feeds (Phylum, Snyk, BleepingComputer) · NIST NVD · CISA KEV  
**Output:** JSON array of prioritised threats — CRITICAL / HIGH / MEDIUM, enriched with CVE IDs, fixed versions, and monitored-package escalation.

## Quick start

```bash
cp .env.example .env
# Set GEMINI_API_KEY and GITHUB_TOKEN
python -m src securityDigest
```

JSON goes to **stdout**. Diagnostics go to **stderr** (structured JSON for Cloud Run).

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | System design, data flow, package layout |
| [Configuration](docs/configuration.md) | Env vars, `sources.yaml` reference, GCP secrets |
| [Deployment](docs/deployment.md) | Cloud Run deployment via `wakellm.sh` |
| [Development](docs/development.md) | Local setup, running tests |
| [Modules](docs/modules.md) | Package and function reference |

## Requirements

- Python 3.12+
- `GEMINI_API_KEY` — [Google AI Studio](https://aistudio.google.com/)
- `GITHUB_TOKEN` — GitHub personal access token (public repo read scope)

## License

MIT
