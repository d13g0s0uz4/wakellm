from __future__ import annotations

REPO_URL = "https://github.com/Deam0on/wakellm"


def get_social_drafts_prompt(
    threats_json: str,
    run_date: str,
    max_tweets: int = 12,
) -> str:
    return f"""You are a DevSecOps content writer producing a daily security digest for software developers.

Date: {run_date}
Input: a JSON list of confirmed npm / PyPI / supply-chain security threats detected in the past 24 hours.

Write social media content for two platforms. Return strictly as JSON with this exact structure:
{{
  "reddit_title": "<news-style title — specific, factual, no clickbait. Pattern: 'N npm/PyPI/supply-chain threats today ({run_date}): CVE-XXXX (package), CVE-XXXX (package), ...' Mention the highest-severity items by name.>",
  "reddit_body": "<Full Reddit markdown post. Structure:

1. One-paragraph intro: date, source count, threat count, past-24h framing.

2. A markdown overview table immediately after the intro with columns:
   | # | Package / Advisory | Ecosystem | Severity | Fix |
   |---|---|---|---|---|
   One row per threat. # is the sequence number. Package / Advisory is the package name plus CVE if present (e.g. `@cap-js/sqlite` · CVE-2026-46421). Severity is CRITICAL/HIGH/MEDIUM. Fix is the patched version or 'Uninstall' or 'Update' as applicable.

3. Then one ### section per threat (same order as the table) with: threat title as heading, **Ecosystem**, **CVE** (if present), **Severity**, a 1-2 sentence summary, **Action Required**, and [Source](<url>).

4. Closing line: 'Automated daily digest — feedback welcome. Repo: {REPO_URL}'

Reddit markdown only, no HTML. Use the source_url values from the input verbatim for source links.>",
  "twitter_thread": [
    "<Tweet 1 (hook, <=280 chars): number of threats, ecosystems affected, top package names, thread emoji 🧵. Include #DevSec #supplychain hashtags.>",
    "<Tweets 2..N (<=280 chars each): one per threat. Format: 'SEVERITY: `package` — one-line impact (CVE-XXXX-XXXX)'. No URLs. Include relevant hashtag e.g. #npm or #PyPI on CRITICAL tweets only.>",
    "<Final tweet (<=280 chars): 'Full report + remediation steps: [REDDIT_LINK]\\nRepo: {REPO_URL}\\n#npm #PyPI #infosec #supplychain'>"
  ]
}}

Rules:
- Each tweet in twitter_thread must be <=280 characters — count carefully
- twitter_thread must have at most {max_tweets} tweets total (hook + per-threat + closing)
- reddit_body source links must use the source_url values from the input verbatim
- [REDDIT_LINK] is a literal placeholder in the final tweet — do not replace it
- Do not invent CVE IDs, package names, or version numbers not present in the input
- The overview table must list every threat; do not omit any
- If a threat has no fixed version, use 'Update' in the Fix column
- Keep tweet 2..N factual and tight — no filler words

Threats JSON:
{threats_json}
"""
