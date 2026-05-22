from __future__ import annotations


def get_social_drafts_prompt(
    threats_json: str,
    run_date: str,
    max_tweets: int = 8,
) -> str:
    return f"""You are a DevSecOps content writer producing a daily security digest for software developers.

Date: {run_date}
Input: a JSON list of confirmed npm / PyPI / supply-chain security threats detected in the past 24 hours.

Write social media content for three platforms. Return strictly as JSON with this exact structure:
{{
  "reddit_title": "<news-style title - specific, factual, no clickbait. Pattern: 'N npm/PyPI/supply-chain threats today ({run_date}): CVE-XXXX-XXXX, <package>, ...' Mention the highest-severity items by name.>",
  "reddit_body": "<Full Reddit markdown post. Open with a one-paragraph intro (date, sources, threat count, past-24h framing). Then for each threat one ### section with the threat title as heading, then **Ecosystem**, **CVE** (if present), **Severity**, summary sentence, action required, and a source link as [Source](<url>). Close with: 'Automated daily digest - feedback welcome.' Reddit markdown only, no HTML.>",
  "twitter_thread": [
    "<Tweet 1 (hook, <=280 chars): number of threats, ecosystems affected, thread marker. E.g. '3 npm/PyPI supply-chain threats in the last 24h: malicious packages, CI/CD compromise, AI tooling SQLi. Thread #infosec #supplychain'>",
    "<Tweets 2..N (<=280 chars each): one per threat. CRITICAL/HIGH/MEDIUM + package or short CVE reference + one-line impact. No URLs in middle tweets.>",
    "<Final tweet (<=280 chars): 'Full report with CVE details and remediation steps: [REDDIT_LINK] #npm #PyPI #infosec #supplychain'>"
  ],
  "linkedin_post": "<Professional narrative, 900-1100 chars total. Business-risk hook opening (no raw CVE IDs). Describe 2-3 top threats in plain language, framed as past-24h detections. One sentence on what engineers should do now. Closing line about following for daily security updates. End with a new line of 6-8 hashtags. Do not exceed 1100 chars.>"
}}

Rules:
- Each tweet in twitter_thread must be <=280 characters - count carefully
- twitter_thread must have at most {max_tweets} tweets total (hook + per-threat + closing)
- linkedin_post must not exceed 1100 characters total
- reddit_body source links must use the source_url values from the input verbatim
- [REDDIT_LINK] is a literal placeholder - do not replace it
- Do not invent CVE IDs, package names, or version numbers not present in the input
- If the input has fewer than 3 threats, cover all of them; do not pad with invented content

Threats JSON:
{threats_json}
"""
