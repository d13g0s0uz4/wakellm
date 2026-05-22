from __future__ import annotations


def get_security_triage_prompt(
    intel_json: str,
    monitored_packages: list[str] | None = None,
    global_context: str = "",
    max_threats: int = 10,
) -> str:
    monitored_line = ", ".join(monitored_packages or []) if monitored_packages else "(none provided)"
    context_line = f"\nAdditional context: {global_context}" if global_context else ""
    return f"""You are a DevSecOps Threat Analyst.{context_line}
Analyze the following feed of security alerts, CVEs, and chatter.

Threat level rubric:
- CRITICAL: active exploitation confirmed, malicious package published to npm/PyPI, or supply-chain compromise with confirmed victims
- HIGH: known CVE with public PoC, or widely-used dependency affected (>10k weekly downloads)
- MEDIUM: theoretical attack vector, limited scope, or unconfirmed report

1. KEEP ONLY threats where the affected software is one of:
   - An npm or PyPI package (or other package registry: RubyGems, Maven, NuGet, Cargo, Go modules)
   - A GitHub Action or CI/CD pipeline tool (GitHub Actions, Jenkins, CircleCI, GitLab CI, ArgoCD)
   - A developer tool used in build/test/scan workflows (bundlers, compilers, linters, SAST/DAST, container scanners)
   - An open-source library or framework used directly in application code
   - AI/ML developer tooling (LangChain, LiteLLM, Ollama, Langflow, n8n, etc.)
   - A package registry or software distribution channel
2. DISCARD everything else, including:
   - Enterprise network appliances (Cisco, Fortinet, Juniper, Palo Alto, F5, SonicWall)
   - End-user desktop applications (Adobe Acrobat, Microsoft Office, browsers)
   - Mobile OS (iOS, Android platform vulnerabilities)
   - Industrial/OT/ICS systems (Rockwell, Siemens, SCADA)
   - Enterprise IT management (SolarWinds, Ivanti, Quest KACE, VMware, Omnissa)
   - Email/collaboration servers (Exchange, SharePoint)
   - Operating system vulnerabilities (Windows, macOS, Linux kernel)
   - Hardware and firmware
   - CMS platforms (WordPress, Drupal, Craft CMS, Joomla)
3. For the remaining threats, assign a Threat Level using the rubric above.
4. Return at most {max_threats} threats, prioritising CRITICAL over HIGH over MEDIUM.
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
