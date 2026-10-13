from urllib.parse import urlparse
from typing import Any, Dict, List
from app.analyzers.base import BaseAnalyzer, AnalysisContext

class RedirectAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "redirect_analyzer"

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        hops: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        raw_chain = context.redirect_history or []
        initial_url = context.raw_url
        final_url = context.normalized_url

        if not raw_chain:
            # Single hop
            parsed = urlparse(final_url)
            hops.append({
                "step": 1,
                "url": final_url,
                "statusCode": context.response_status or 200,
                "domain": parsed.hostname or context.domain,
                "isHttps": final_url.startswith("https://"),
                "isExternal": False
            })
        else:
            for idx, hop in enumerate(raw_chain):
                hop_url = hop.get("url", "")
                parsed = urlparse(hop_url)
                hop_domain = parsed.hostname or ""
                hops.append({
                    "step": idx + 1,
                    "url": hop_url,
                    "statusCode": hop.get("status_code", 301),
                    "domain": hop_domain,
                    "isHttps": hop_url.startswith("https://"),
                    "isExternal": hop_domain.lower() != context.domain.lower()
                })

            if len(hops) > 0:
                final_url = hops[-1]["url"]

        total_hops = len(hops)
        has_suspicious = False

        # 1. Check for protocol downgrade (HTTPS -> HTTP)
        for i in range(len(hops) - 1):
            if hops[i]["isHttps"] and not hops[i + 1]["isHttps"]:
                has_suspicious = True
                findings.append({
                    "id": "redir-downgrade",
                    "category": "REDIRECTS",
                    "title": "Insecure Protocol Downgrade (HTTPS to HTTP)",
                    "status": "FAIL",
                    "impact": "CRITICAL",
                    "description": f"The website redirects encrypted traffic from {hops[i]['url']} to unencrypted HTTP ({hops[i+1]['url']}).",
                    "remediation": "Ensure all redirects retain or upgrade to secure HTTPS."
                })
                break

        # 2. Check for excessive redirect hops
        if total_hops > 3:
            findings.append({
                "id": "redir-excessive",
                "category": "REDIRECTS",
                "title": f"High Redirect Count ({total_hops} hops)",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": f"Encountered {total_hops} sequential redirects before reaching final destination, increasing latency and tracking exposure.",
                "remediation": "Optimize redirect chains to directly target the canonical URL."
            })

        # 3. Check for cross-domain redirects
        external_hops = [h for h in hops if h["isExternal"]]
        if external_hops:
            domains = list(set([h["domain"] for h in external_hops]))
            findings.append({
                "id": "redir-cross-domain",
                "category": "REDIRECTS",
                "title": "Cross-Domain Redirect Chain",
                "status": "INFO",
                "impact": "LOW",
                "description": f"Traffic redirects across different domains: {', '.join(domains)}.",
            })

        return {
            "redirects": {
                "initialUrl": initial_url,
                "finalUrl": final_url,
                "totalHops": total_hops,
                "hasSuspiciousRedirect": has_suspicious,
                "chain": hops
            },
            "findings": findings
        }
