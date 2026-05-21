from __future__ import annotations

import json
import logging
import re
from typing import Any, TypeVar

from google import genai
from google.genai import types
from pydantic import BaseModel

from src.config.env import env

T = TypeVar("T")

_log = logging.getLogger(__name__)

_SAFETY = [
    types.SafetySetting(
        category="HARM_CATEGORY_DANGEROUS_CONTENT",
        threshold="BLOCK_ONLY_HIGH",
    )
]

_REDACT_PATTERN = re.compile(r"[A-Za-z0-9_\-]{20,}")


def _redact(text: str) -> str:
    return _REDACT_PATTERN.sub("[redacted]", text)


def _is_json_mime_tool_error(exc: Exception) -> bool:
    """Detect Gemini API incompatibility: tools + response_mime_type=application/json."""
    message = str(exc).lower()
    return "tool use" in message and "application/json" in message and "unsupported" in message


def is_quota_exhausted_error(exc: Exception) -> bool:
    """Detect hard quota-cap errors that should fail fast without retrying."""
    message = str(exc).lower()
    return (
        "resource_exhausted" in message
        and "spending cap" in message
    )


def _extract_json_payload(raw: str) -> str:
    """Extract the first complete JSON object/array from a model response."""
    cleaned = re.sub(r"^```[a-z]*\n?", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```$", "", cleaned.strip(), flags=re.MULTILINE)

    object_start = cleaned.find("{")
    array_start = cleaned.find("[")
    candidates: list[tuple[int, str, str]] = []
    if object_start != -1:
        candidates.append((object_start, "{", "}"))
    if array_start != -1:
        candidates.append((array_start, "[", "]"))
    if not candidates:
        raise ValueError("No JSON found in Gemini response")

    start, open_char, close_char = min(candidates, key=lambda c: c[0])

    depth = 0
    in_string = False
    escape = False
    for idx, ch in enumerate(cleaned[start:], start=start):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return cleaned[start : idx + 1]

    raise ValueError("No JSON found in Gemini response")


class GeminiService:
    """
    Wraps the google-genai SDK.

    generate_text  — returns raw string.
    generate_json  — uses response_schema for native structured output when the
                     schema is a Pydantic model; falls back to JSON parsing otherwise.
    """

    def __init__(self) -> None:
        self._client = genai.Client(api_key=env.GEMINI_API_KEY)
        self._model = env.GEMINI_MODEL
        self._fallback_notice_emitted = False
        self._quota_notice_emitted = False

    def _make_config(
        self,
        use_search: bool,
        temperature: float,
        response_mime_type: str | None = None,
        response_schema: type | None = None,
    ) -> types.GenerateContentConfig:
        kwargs: dict[str, Any] = {
            "temperature": temperature,
            "safety_settings": _SAFETY,
        }
        if use_search:
            kwargs["tools"] = [types.Tool(google_search=types.GoogleSearch())]
        if response_mime_type:
            kwargs["response_mime_type"] = response_mime_type
        if response_schema is not None:
            kwargs["response_schema"] = response_schema
        return types.GenerateContentConfig(**kwargs)

    async def generate_text(
        self,
        prompt: str,
        use_search: bool = False,
        temperature: float = 0.1,
        retries: int = 2,
        retry_delay_ms: int = 1000,
    ) -> str:
        config = self._make_config(use_search=use_search, temperature=temperature)
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            try:
                response = await self._client.aio.models.generate_content(
                    model=self._model,
                    contents=prompt.strip(),
                    config=config,
                )
                text = response.text
                if not text:
                    raise ValueError("Gemini response contained no text")
                return text
            except Exception as exc:
                last_error = exc

                if is_quota_exhausted_error(exc):
                    if not self._quota_notice_emitted:
                        _log.error(
                            "[gemini] Quota exhausted (monthly spend cap). Failing fast; retries disabled until billing cap is increased."
                        )
                        self._quota_notice_emitted = True
                    raise

                msg = _redact(str(exc))
                _log.warning("[gemini] Attempt %d failed: %s", attempt + 1, msg)
                if attempt < retries:
                    from src.utils.async_utils import sleep
                    await sleep(retry_delay_ms * (attempt + 1))

        raise last_error or RuntimeError("Gemini request failed with unknown error")

    async def generate_json(
        self,
        prompt: str,
        schema: type,
        use_search: bool = False,
        temperature: float = 0.1,
        retries: int = 2,
        retry_delay_ms: int = 1000,
        model_override: str | None = None,
    ) -> Any:
        """
        Generate structured output.
        If schema is a Pydantic BaseModel subclass, uses response_schema for
        native structured output. Otherwise parses JSON from the text response.
        """
        use_native = isinstance(schema, type) and issubclass(schema, BaseModel)
        prompt_text = prompt.strip()
        fallback_to_text_json = False
        fallback_notice_logged = False
        model_to_use = model_override if model_override else self._model

        if use_native:
            config = self._make_config(
                use_search=use_search,
                temperature=temperature,
                response_mime_type="application/json",
                response_schema=schema,
            )
        elif use_search:
            config = self._make_config(
                use_search=use_search,
                temperature=temperature,
            )
        else:
            config = self._make_config(
                use_search=use_search,
                temperature=temperature,
                response_mime_type="application/json",
            )

        last_error: Exception | None = None

        for attempt in range(retries + 1):
            try:
                response = await self._client.aio.models.generate_content(
                    model=model_to_use,
                    contents=prompt_text,
                    config=config,
                )
                raw = response.text
                if not raw:
                    raise ValueError("Gemini response contained no text")

                if use_native and not fallback_to_text_json:
                    return schema.model_validate_json(raw)

                payload = _extract_json_payload(raw)
                parsed = json.loads(payload)
                if use_native:
                    return schema.model_validate(parsed)
                return parsed
            except Exception as exc:
                last_error = exc

                if is_quota_exhausted_error(exc):
                    if not self._quota_notice_emitted:
                        _log.error(
                            "[gemini] Quota exhausted (monthly spend cap). Failing fast; retries disabled until billing cap is increased."
                        )
                        self._quota_notice_emitted = True
                    raise

                if use_search and not fallback_to_text_json and _is_json_mime_tool_error(exc):
                    fallback_to_text_json = True
                    config = self._make_config(
                        use_search=use_search,
                        temperature=temperature,
                    )
                    prompt_text = (
                        f"{prompt_text}\n\n"
                        "Return ONLY valid JSON. Do not include markdown fences or commentary."
                    )
                    if not fallback_notice_logged and not self._fallback_notice_emitted:
                        _log.info(
                            "[gemini] Falling back to text+JSON parsing for search-enabled structured output."
                        )
                        fallback_notice_logged = True
                        self._fallback_notice_emitted = True
                    continue

                msg = _redact(str(exc))
                _log.warning("[gemini] Attempt %d failed: %s", attempt + 1, msg)

                if attempt < retries:
                    from src.utils.async_utils import sleep
                    await sleep(retry_delay_ms * (attempt + 1))

        raise last_error or RuntimeError("Gemini JSON request failed")
