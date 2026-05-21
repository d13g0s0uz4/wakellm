from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from src.gemini import GeminiService
from src.utils.llm_schemas import SocialDrafts
from src.security_digest.social_prompts import get_social_drafts_prompt

_log = logging.getLogger(__name__)


async def run_social_drafts(
    threats: list[dict],
    gemini: GeminiService,
    run_date: str | None = None,
    max_tweets: int = 8,
) -> SocialDrafts | None:
    if not threats:
        _log.warning("[social] No threats — skipping social draft generation.")
        return None

    run_date = run_date or datetime.now(timezone.utc).strftime("%B %d, %Y")
    prompt = get_social_drafts_prompt(
        json.dumps(threats, indent=2),
        run_date=run_date,
        max_tweets=max_tweets,
    )

    try:
        result = await gemini.generate_json(
            prompt,
            schema=SocialDrafts,
            use_search=False,
            temperature=0.4,
        )
        _log.info("[social] Social drafts generated successfully.")
        return result
    except Exception as exc:
        _log.error("[social] Draft generation failed: %s", exc)
        return None
