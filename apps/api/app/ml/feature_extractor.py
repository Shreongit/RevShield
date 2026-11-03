
import ipaddress
import math
import re
from typing import Dict, Union
from urllib.parse import urlsplit

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
    "query_param_count",
]

SUSPICIOUS_TOKENS = [
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
    "apple",
    "paypal",
]


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy for a string."""

    if not value:
        return 0.0

    frequencies = {}

    for character in value:
        frequencies[character] = frequencies.get(character, 0) + 1

    entropy = 0.0

    for count in frequencies.values():
        probability = count / len(value)
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def _normalize_url(raw_url: str) -> str:
    """Add HTTPS when no HTTP scheme is supplied."""

    url = raw_url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "https://" + url

    return url


def _is_ip_address(hostname: str) -> bool:
    """Detect valid IPv4 and IPv6 address literals."""

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features_from_url(
    raw_url: str,
) -> Dict[str, Union[float, int]]:
    """
    Extract the existing 19 URL features.

    Suspicious-token detection intentionally examines only the hostname
    and path. Query parameters are counted separately but their values
    do not directly trigger suspicious-token detection.
    """

    if not isinstance(raw_url, str):
        raise TypeError("URL must be a string.")

    url = _normalize_url(raw_url)

    try:
        parsed = urlsplit(url)
        domain = (parsed.hostname or "").lower()
    except ValueError:
        parsed = urlsplit("https://invalid.example")
        domain = "invalid.example"

    path = (parsed.path or "").lower()
    query = parsed.query or ""
    full_url = url.lower()

    # Hostname and path are used for lexical threat indicators.
    hostname_and_path = f"{domain}{path}"

    # Basic URL measurements.
    url_length = len(full_url)
    domain_length = len(domain)
    path_length = len(path)

    dot_count = full_url.count(".")
    hyphen_count = full_url.count("-")
    at_count = full_url.count("@")
    question_count = full_url.count("?")
    percent_count = full_url.count("%")
    slash_count = full_url.count("/")

    digit_count = sum(
        1 for character in full_url if character.isdigit()
    )

    letter_count = sum(
        1 for character in full_url if character.isalpha()
    )

    digit_ratio = round(
        digit_count / (letter_count + 1),
        4,
    )

    # Domain structure.
    domain_parts = domain.rstrip(".").split(".") if domain else []

    subdomain_count = max(
        0,
        len(domain_parts) - 2,
    )

    domain_entropy = calculate_entropy(domain)

    # IP and IDN detection.
    has_ip_host = int(_is_ip_address(domain))

    has_punycode = int(
        any(
            label.startswith("xn--")
            for label in domain_parts
        )
    )

    # Protocol.
    is_https = int(parsed.scheme.lower() == "https")

    # Suspicious tokens: hostname and path only.
    has_suspicious_token = int(
        any(
            token in hostname_and_path
            for token in SUSPICIOUS_TOKENS
        )
    )

    # TLD approximation. This intentionally preserves the existing
    # feature definition rather than introducing a public-suffix dependency.
    tld = domain_parts[-1] if domain_parts else ""
    tld_length = len(tld)

    # Query parameters remain a separate structural feature.
    query_param_count = (
        len([part for part in query.split("&") if part])
        if query
        else 0
    )

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
        "query_param_count": query_param_count,
    }


def features_to_vector(
    features: Dict[str, Union[float, int]],
) -> np.ndarray:
    """Convert extracted features into the model's expected input vector."""

    missing_features = [
        name for name in FEATURE_NAMES if name not in features
    ]

    if missing_features:
        raise ValueError(
            f"Missing required model features: {missing_features}"
        )

    return np.array(
        [[features[name] for name in FEATURE_NAMES]],
        dtype=np.float32,
    )
