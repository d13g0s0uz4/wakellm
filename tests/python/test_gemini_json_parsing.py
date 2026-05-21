from __future__ import annotations

import json
import unittest

from src.gemini import _extract_json_payload


class GeminiJsonParsingTests(unittest.TestCase):
    def test_extracts_fenced_json_object(self) -> None:
        raw = """Here is your result:\n```json\n{\"final_stories\": [{\"headline\": \"A\"}]}\n```\nThanks"""
        payload = _extract_json_payload(raw)
        data = json.loads(payload)
        self.assertEqual(data["final_stories"][0]["headline"], "A")

    def test_extracts_first_complete_json_array(self) -> None:
        raw = "prefix text\n[{\"a\": 1}, {\"b\": 2}]\nextra trailing text"
        payload = _extract_json_payload(raw)
        data = json.loads(payload)
        self.assertEqual(len(data), 2)
        self.assertEqual(data[1]["b"], 2)

    def test_raises_when_no_json_present(self) -> None:
        with self.assertRaises(ValueError):
            _extract_json_payload("no structured payload here")


if __name__ == "__main__":
    unittest.main()
