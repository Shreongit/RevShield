import math
import re
from urllib.parse import urlparse
from typing import Dict, List, Union
import numpy as np

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "question_count",
    "percent_count",
    "slash_count",
    "digit_count",
    "digit_ratio",
    "subdomain_count",
    "domain_entropy",
    "has_ip_host",
    "has_punycode",
    "is_https",
    "has_suspicious_token",
    "tld_length",
    "query_param_count"
]

SUSPICIOUS_TOKENS = [
    "login", "signin", "verify", "account", "banking", "secure", "update", "wallet",
    "credential", "recover", "authenticate", "confirm", "billing", "apple", "paypal"
]

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features_from_url(raw_url: str) -> Dict[str, Union[float, int]]:
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("https://invalid.example")

    domain = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full_url = url.lower()

    # Features
    url_length = len(full_url)
    domain_length = len(domain)
    path_length = len(path)
    dot_count = full_url.count(".")
    hyphen_count = full_url.count("-")
    at_count = full_url.count("@")
    question_count = full_url.count("?")
    percent_count = full_url.count("%")
    slash_count = full_url.count("/")
    digit_count = sum(1 for c in full_url if c.isdigit())
    letter_count = sum(1 for c in full_url if c.isalpha())
    digit_ratio = round(digit_count / (letter_count + 1), 4)

    subdomain_parts = domain.split(".")
    subdomain_count = max(0, len(subdomain_parts) - 2)
    domain_entropy = calculate_entropy(domain)

    has_ip_host = 1 if bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)) else 0
    has_punycode = 1 if ("xn--" in domain) else 0
    is_https = 1 if url.startswith("https://") else 0
    has_suspicious_token = 1 if any(t in full_url for t in SUSPICIOUS_TOKENS) else 0

    tld = subdomain_parts[-1] if subdomain_parts else ""
    tld_length = len(tld)
    query_param_count = len(query.split("&")) if query else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_count": at_count,
        "question_count": question_count,
        "percent_count": percent_count,
        "slash_count": slash_count,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "subdomain_count": subdomain_count,
        "domain_entropy": domain_entropy,
        "has_ip_host": has_ip_host,
        "has_punycode": has_punycode,
        "is_https": is_https,
        "has_suspicious_token": has_suspicious_token,
        "tld_length": tld_length,
        "query_param_count": query_param_count
    }

def features_to_vector(features: Dict[str, Union[float, int]]) -> np.ndarray:
    return np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float32)
