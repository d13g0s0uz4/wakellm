"""
wakellm-security — entry point.
Usage (Cloud Run): python -m src securityDigest
Usage (local):     python -m src securityDigest
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import sys
from typing import TextIO


class _CloudRunFormatter(logging.Formatter):
    """Emit single-line JSON so Cloud Run picks up the 'severity' field."""

    def format(self, record: logging.LogRecord) -> str:
        return _json.dumps({
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        })


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_CloudRunFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


_log = logging.getLogger(__name__)


def _print_usage(*, stream: TextIO = sys.stdout) -> None:
    print("""
wakellm-security CLI

Usage:
  python -m src securityDigest

Commands:
  securityDigest   Collect supply-chain threat intel from GitHub Advisory,
                   Reddit, RSS feeds, NIST NVD, and CISA KEV; triage with
                   Gemini; write JSON to stdout.

Config (env vars or GCP Secret Manager):
  GEMINI_API_KEY              (required) Gemini API key
  GITHUB_TOKEN                (required) GitHub personal access token
  SOURCES_CONFIG              (optional) Path to sources YAML/JSON (default: config/sources.yaml)
  SECURITY_MONITORED_PACKAGES (optional) Comma-separated monitored package list
  LLM_GLOBAL_CONTEXT          (optional) Extra context prepended to LLM prompts
  GEMINI_MODEL                (optional) Gemini model name (default: gemini-2.5-flash-lite)
""", file=stream)


async def _main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in {"-h", "--help"}:
        _print_usage()
        return

    command = args[0]

    if command != "securityDigest":
        _log.error("Unknown command: %r", command)
        _print_usage(stream=sys.stderr)
        sys.exit(1)

    _log.info("command=%s", command)

    from src.security_digest import run_security_digest
    await run_security_digest()


def main() -> None:
    _configure_logging()
    try:
        asyncio.run(_main())
    except Exception as exc:
        import traceback
        _log.error("Fatal error: %s: %s", type(exc).__name__, exc)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

