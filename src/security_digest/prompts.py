from __future__ import annotations


def get_security_triage_prompt(
    intel_json: str,
    monitored_packages: list[str] | None = None,
    global_context: str = "",
) -> str:
    monitored_line = ", ".join(monitored_packages or []) if monitored_packages else "(none provided)"
    context_line = f"\nAdditional context: {global_context}" if global_context else ""
    return f"""You are a DevSecOps Threat Analyst.{context_line}
Analyze the following feed of security alerts, CVEs, and chatter.

Threat level rubric:
- CRITICAL: active exploitation confirmed, malicious package published to npm/PyPI, or supply-chain compromise with confirmed victims
- HIGH: known CVE with public PoC, or widely-used dependency affected (>10k weekly downloads)
- MEDIUM: theoretical attack vector, limited scope, or unconfirmed report

1. Discard any vulnerabilities related to WordPress, Windows OS, or hardware.
2. Isolate threats specifically related to: 'npm', 'PyPI', 'supply chain', 'typosquatting', or 'malicious packages'.
3. For the relevant threats, assign a Threat Level using the rubric above.
4. Return at most 10 threats, prioritising CRITICAL over HIGH over MEDIUM.
5. Output strictly as JSON:
{{
  "threats": [
    {{
      "title": "...",
      "ecosystem": "npm or PyPI",
      "threat_level": "CRITICAL",
      "summary": "...",
      "source_url": "https://...",
      "action_required": "...",
      "cve_id": "CVE-YYYY-NNNN",
      "fixed_version": "1.2.3"
    }}
  ]
}}

Rules:
- Include cve_id only when confidently present in the input; otherwise use null or omit it.
- Include fixed_version only when the input provides an explicit patched/fixed version; otherwise use null or omit it.
- source_url must be taken exactly from the input feed; do not construct or guess URLs.
- If no supply-chain or npm/PyPI threats are present, return {{"threats": []}}.

Monitored internal dependencies (prioritize when present in a threat):
{monitored_line}

Feed JSON:
{intel_json}
"""
