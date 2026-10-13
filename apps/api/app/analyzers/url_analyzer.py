import math
import re
from urllib.parse import urlparse
from typing import Any, Dict, List
from app.analyzers.base import BaseAnalyzer, AnalysisContext

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "banking", "secure", "update", "wallet",
    "credential", "recover", "authenticate", "confirm", "billing", "support-apple", "paypa1"
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "work", "loan", "click", "fit", "buzz"
}

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 3)

class URLAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "url_analyzer"

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        parsed = urlparse(context.normalized_url)
        domain = context.domain.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = context.normalized_url.lower()

        indicators: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        # 1. IP literal check
        is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
        indicators.append({
            "name": "ip_as_host",
            "detected": is_ip_host,
            "description": "Website uses raw IP address instead of a recognized domain name",
            "weight": 0.85,
            "value": domain if is_ip_host else None
        })
        if is_ip_host:
            findings.append({
                "id": "url-ip-host",
                "category": "THREAT",
                "title": "Raw IP Address Host",
                "status": "WARN",
                "impact": "HIGH",
                "description": "Connecting directly via IP address is common in phishing attacks and bypasses standard domain reputation systems.",
                "remediation": "Configure a legitimate domain name with valid DNS and TLS certificates."
            })

        # 2. Homograph / Punycode check (xn--)
        is_punycode = domain.startswith("xn--") or ".xn--" in domain
        indicators.append({
            "name": "punycode_homograph",
            "detected": is_punycode,
            "description": "Domain uses Internationalized Domain Name (IDN) Punycode encoding",
            "weight": 0.7,
            "value": is_punycode
        })
        if is_punycode:
            findings.append({
                "id": "url-punycode",
                "category": "THREAT",
                "title": "Punycode / IDN Domain Detected",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": "Punycode domains can visually impersonate legitimate brands using lookalike Unicode characters.",
                "remediation": "Verify the exact ASCII punycode translation matches intended ownership."
            })

        # 3. Suspicious keywords in URL/path
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
        has_suspicious_keywords = len(matched_keywords) > 0
        indicators.append({
            "name": "suspicious_keywords",
            "detected": has_suspicious_keywords,
            "description": f"Contains security/credential related terms ({', '.join(matched_keywords[:3])})",
            "weight": 0.4,
            "value": matched_keywords
        })

        # 4. Excessive subdomain depth
        subdomain_parts = domain.split(".")
        excessive_subdomains = len(subdomain_parts) >= 4
        indicators.append({
            "name": "excessive_subdomains",
            "detected": excessive_subdomains,
            "description": f"Domain contains {len(subdomain_parts)} parts, which exceeds standard 2-3 level hierarchy",
            "weight": 0.5,
            "value": len(subdomain_parts)
        })

        # 5. Shannon Entropy
        entropy = calculate_shannon_entropy(domain)
        high_entropy = entropy > 4.2
        indicators.append({
            "name": "high_entropy_domain",
            "detected": high_entropy,
            "description": f"Domain character randomness score is {entropy} (high randomness often indicates DGA/temporary phishing hosts)",
            "weight": 0.6,
            "value": entropy
        })

        # 6. Suspicious TLD
        tld = domain.split(".")[-1] if "." in domain else ""
        suspicious_tld = tld in SUSPICIOUS_TLDS
        indicators.append({
            "name": "unusual_tld",
            "detected": suspicious_tld,
            "description": f"Top-level domain (.{tld}) is frequently associated with disposable campaigns",
            "weight": 0.45,
            "value": tld
        })

        # 7. URL length
        excessive_length = len(context.normalized_url) > 120
        indicators.append({
            "name": "excessive_url_length",
            "detected": excessive_length,
            "description": f"URL length is {len(context.normalized_url)} characters",
            "weight": 0.3,
            "value": len(context.normalized_url)
        })

        return {
            "domain": domain,
            "tld": tld,
            "entropy": entropy,
            "indicators": indicators,
            "findings": findings
        }
