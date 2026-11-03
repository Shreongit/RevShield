
import ipaddress
import math
import re

from urllib.parse import urlparse
from typing import Any, Dict, List

from app.analyzers.base import BaseAnalyzer, AnalysisContext


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "account",
    "banking",
    "secure",
    "update",
    "wallet",
    "credential",
    "recover",
    "authenticate",
    "confirm",
    "billing",
    "support-apple",
    "paypa1"
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq",
    "top", "work", "loan", "click", "fit", "buzz"
}


def calculate_shannon_entropy(text: str) -> float:

    if not text:
        return 0.0

    freq = {}

    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0

    for count in freq.values():
        probability = count / len(text)
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def is_ip_address(hostname: str) -> bool:

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True

    except ValueError:
        return False


def normalize_hostname(hostname: str) -> str:

    if not hostname:
        return ""

    return hostname.strip().rstrip(".").lower()


def contains_suspicious_keyword(value: str) -> List[str]:

    detected = []

    for keyword in SUSPICIOUS_KEYWORDS:

        pattern = (
            r"(?<![a-z0-9])"
            + re.escape(keyword)
            + r"(?![a-z0-9])"
        )

        if re.search(pattern, value, re.IGNORECASE):
            detected.append(keyword)

    return detected


class URLAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "url_analyzer"

    async def analyze(
        self,
        context: AnalysisContext
    ) -> Dict[str, Any]:

        parsed = urlparse(context.normalized_url)

        domain = normalize_hostname(
            parsed.hostname or context.domain
        )

        path = (parsed.path or "").lower()

        full_url = context.normalized_url.lower()

        indicators: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        # ==========================================
        # 1. IP ADDRESS DETECTION
        # ==========================================

        is_ip_host = is_ip_address(domain)

        indicators.append({
            "name": "ip_as_host",
            "detected": is_ip_host,
            "description": (
                "Website uses a direct IPv4 or IPv6 address "
                "instead of a conventional domain name."
            ),
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
                "description": (
                    "The destination uses a direct IP address. "
                    "This can occur in phishing infrastructure "
                    "and should be verified."
                ),
                "remediation": (
                    "Verify the destination and confirm that "
                    "the IP address belongs to the expected service."
                )
            })

        # ==========================================
        # 2. PUNYCODE / IDN DETECTION
        # ==========================================

        domain_labels = domain.split(".")

        is_punycode = any(
            label.startswith("xn--")
            for label in domain_labels
        )

        indicators.append({
            "name": "punycode_homograph",
            "detected": is_punycode,
            "description": (
                "Domain contains an IDN Punycode label "
                "that may require visual identity verification."
            ),
            "weight": 0.7,
            "value": domain if is_punycode else None
        })

        if is_punycode:

            findings.append({
                "id": "url-punycode",
                "category": "THREAT",
                "title": "Punycode / IDN Domain Detected",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    "The hostname contains an internationalized "
                    "domain label encoded using Punycode. "
                    "This alone does not establish malicious intent."
                ),
                "remediation": (
                    "Verify the decoded internationalized domain "
                    "and confirm that it belongs to the intended owner."
                )
            })

        # ==========================================
        # 3. SUSPICIOUS KEYWORDS
        # ==========================================

        # Inspect hostname and path separately.
        # Query parameters are excluded to reduce false positives.

        keyword_source = f"{domain}/{path}"

        matched_keywords = contains_suspicious_keyword(
            keyword_source
        )

        has_suspicious_keywords = bool(matched_keywords)

        indicators.append({
            "name": "suspicious_keywords",
            "detected": has_suspicious_keywords,
            "description": (
                "Credential or account-related keywords detected: "
                + ", ".join(matched_keywords[:3])
                if matched_keywords
                else "No configured suspicious keywords detected."
            ),
            "weight": 0.4,
            "value": matched_keywords
        })

        # ==========================================
        # 4. SUBDOMAIN DEPTH
        # ==========================================

        if is_ip_host:
            subdomain_count = 0
        else:
            subdomain_count = max(
                0,
                len(domain_labels) - 2
            )

        excessive_subdomains = subdomain_count >= 2

        indicators.append({
            "name": "excessive_subdomains",
            "detected": excessive_subdomains,
            "description": (
                f"Hostname contains {subdomain_count} "
                "subdomain levels."
            ),
            "weight": 0.5,
            "value": subdomain_count
        })

        # ==========================================
        # 5. DOMAIN ENTROPY
        # ==========================================

        # Remove separators so punctuation does not
        # artificially influence character distribution.

        entropy_input = domain.replace(".", "")

        entropy = calculate_shannon_entropy(
            entropy_input
        )

        high_entropy = entropy > 4.2

        indicators.append({
            "name": "high_entropy_domain",
            "detected": high_entropy,
            "description": (
                f"Hostname character entropy is {entropy}. "
                "High entropy may indicate randomly generated "
                "or unusual domain labels."
            ),
            "weight": 0.6,
            "value": entropy
        })

        # ==========================================
        # 6. TOP-LEVEL DOMAIN
        # ==========================================

        tld = (
            domain_labels[-1]
            if domain_labels and not is_ip_host
            else ""
        )

        suspicious_tld = tld in SUSPICIOUS_TLDS

        indicators.append({
            "name": "unusual_tld",
            "detected": suspicious_tld,
            "description": (
                f"Top-level domain .{tld} belongs to the "
                "configured unusual-TLD heuristic list."
                if suspicious_tld
                else f"Top-level domain .{tld} is not in the "
                     "configured unusual-TLD list."
            ),
            "weight": 0.45,
            "value": tld
        })

        # ==========================================
        # 7. URL LENGTH
        # ==========================================

        url_length = len(context.normalized_url)

        excessive_length = url_length > 120

        indicators.append({
            "name": "excessive_url_length",
            "detected": excessive_length,
            "description": (
                f"URL length is {url_length} characters."
            ),
            "weight": 0.3,
            "value": url_length
        })

        # ==========================================
        # 8. FINAL RESULT
        # ==========================================

        return {
            "domain": domain,
            "tld": tld,
            "entropy": entropy,
            "indicators": indicators,
            "findings": findings
        }
