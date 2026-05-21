from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

os.environ.setdefault("GEMINI_API_KEY", "test-gemini-key")
os.environ.setdefault("GITHUB_TOKEN", "test-github-token")

from pydantic import BaseModel

from src.gemini import GeminiService, _is_json_mime_tool_error, is_quota_exhausted_error


class _StoryResponse(BaseModel):
    headline: str


class GeminiServiceFallbackTests(unittest.IsolatedAsyncioTestCase):
    @patch("src.services.gemini.genai.Client")
    async def test_generate_json_search_dict_does_not_force_json_mime(self, client_cls) -> None:
        mock_client = client_cls.return_value
        generate_content = AsyncMock(
            return_value=SimpleNamespace(text='{"items": [{"headline": "A"}]}')
        )
        mock_client.aio.models.generate_content = generate_content

        svc = GeminiService()
        result = await svc.generate_json("test prompt", schema=dict, use_search=True)

        self.assertEqual(result["items"][0]["headline"], "A")
        self.assertEqual(generate_content.await_count, 1)

        first_config = generate_content.await_args_list[0].kwargs["config"]
        self.assertIsNone(first_config.response_mime_type)

    @patch("src.services.gemini.genai.Client")
    async def test_generate_json_fallback_validates_pydantic_schema(self, client_cls) -> None:
        mock_client = client_cls.return_value
        generate_content = AsyncMock(
            side_effect=[
                Exception("400 INVALID_ARGUMENT: Tool use with a response mime type: 'application/json' is unsupported"),
                SimpleNamespace(text='{"headline": "Validated"}'),
            ]
        )
        mock_client.aio.models.generate_content = generate_content

        svc = GeminiService()
        result = await svc.generate_json("test prompt", schema=_StoryResponse, use_search=True)

        self.assertIsInstance(result, _StoryResponse)
        self.assertEqual(result.headline, "Validated")

    @patch("src.services.gemini.genai.Client")
    async def test_generate_json_fails_fast_on_quota_exhaustion(self, client_cls) -> None:
        mock_client = client_cls.return_value
        generate_content = AsyncMock(
            side_effect=Exception(
                "429 RESOURCE_EXHAUSTED: Your project has exceeded its monthly spending cap"
            )
        )
        mock_client.aio.models.generate_content = generate_content

        svc = GeminiService()
        with self.assertRaises(Exception):
            await svc.generate_json("test prompt", schema=dict, use_search=True)

        self.assertEqual(generate_content.await_count, 1)


class GeminiServiceErrorDetectionTests(unittest.TestCase):
    def test_detects_tool_json_mime_error(self) -> None:
        err = Exception("Tool use with a response mime type: 'application/json' is unsupported")
        self.assertTrue(_is_json_mime_tool_error(err))

    def test_ignores_other_errors(self) -> None:
        err = Exception("400 INVALID_ARGUMENT: something else")
        self.assertFalse(_is_json_mime_tool_error(err))

    def test_detects_quota_exhausted_error(self) -> None:
        err = Exception("429 RESOURCE_EXHAUSTED: Your project has exceeded its monthly spending cap")
        self.assertTrue(is_quota_exhausted_error(err))

    def test_ignores_non_quota_resource_exhausted_error(self) -> None:
        err = Exception("429 RESOURCE_EXHAUSTED: rate limit exceeded")
        self.assertFalse(is_quota_exhausted_error(err))


if __name__ == "__main__":
    unittest.main()
