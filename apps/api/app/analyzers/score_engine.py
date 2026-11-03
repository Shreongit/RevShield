
import math
from typing import Any, Dict, List


class ScoreEngine:
    @staticmethod
    def calculate_scores(
        url_data: Dict[str, Any],
        tls_data: Dict[str, Any],
        headers_data: Dict[str, Any],
        redirects_data: Dict[str, Any],
        privacy_data: Dict[str, Any],
        cookies_data: Dict[str, Any],
        threat_data: Dict[str, Any]
    ) -> Dict[str, Any]:

        factors: List[Dict[str, Any]] = []

        def safe_dict(value: Any) -> Dict[str, Any]:
            return value if isinstance(value, dict) else {}

        def safe_list(value: Any) -> List[Any]:
            return value if isinstance(value, list) else []

        def safe_count(value: Any) -> int:
            try:
                return max(0, int(value))
            except (TypeError, ValueError, OverflowError):
                return 0

        def add_factor(
            name: str,
            impact: int,
            reason: str,
            category: str
        ) -> None:
            factors.append({
                "name": name,
                "impactPoints": impact,
                "reason": reason,
                "type": "NEGATIVE" if impact < 0 else "INFO",
                "scoreCategory": category
            })

        # ==========================================
        # 1. SECURITY SCORE
        # ==========================================

        sec_points = 100

        tls_info = safe_dict(safe_dict(tls_data).get("tls_info"))
        tls_valid = tls_info.get("valid")

        if tls_valid is False:
            sec_points -= 45
            add_factor(
                "Invalid or Missing TLS",
                -45,
                "The scanner confirmed that the TLS certificate "
                "is invalid or unavailable.",
                "SECURITY"
            )

        elif tls_valid is True:
            add_factor(
                "Valid TLS Certificate",
                0,
                f"Valid certificate issued by "
                f"{tls_info.get('issuer', 'CA')} using "
                f"{tls_info.get('protocolVersion', 'TLS')}. "
                "No bonus points are awarded.",
                "SECURITY"
            )

        else:
            add_factor(
                "TLS Status Unknown",
                0,
                "The scanner could not determine TLS certificate "
                "validity. No invalid-certificate penalty was applied.",
                "SECURITY"
            )

        headers = safe_list(safe_dict(headers_data).get("headers"))

        header_map = {
            header.get("headerName", "").lower(): header
            for header in headers
            if isinstance(header, dict)
            and isinstance(header.get("headerName"), str)
        }

        # Content Security Policy
        csp = safe_dict(header_map.get("content-security-policy"))

        if not csp.get("present", False):
            sec_points -= 15
            add_factor(
                "Missing CSP Header",
                -15,
                "Absence of Content Security Policy increases "
                "exposure to script injection attacks.",
                "SECURITY"
            )

        elif csp.get("status") == "OPTIMAL":
            add_factor(
                "Strict CSP Enabled",
                0,
                "The website has an optimal Content Security Policy. "
                "No additional bonus is applied.",
                "SECURITY"
            )

        # HTTP Strict Transport Security
        hsts = safe_dict(
            header_map.get("strict-transport-security")
        )

        if not hsts.get("present", False):
            sec_points -= 12
            add_factor(
                "Missing HSTS Header",
                -12,
                "The website does not advertise an HSTS response header.",
                "SECURITY"
            )
        else:
            add_factor(
                "HSTS Header Present",
                0,
                "The website advertises an HSTS response header.",
                "SECURITY"
            )

        # Clickjacking protection
        xfo = safe_dict(header_map.get("x-frame-options"))

        csp_value = (
            csp.get("value")
            or csp.get("headerValue")
            or csp.get("header_value")
            or ""
        )

        has_frame_ancestors = any(
            directive.strip().lower().startswith("frame-ancestors ")
            or directive.strip().lower() == "frame-ancestors"
            for directive in str(csp_value).split(";")
        )

        has_clickjacking_protection = (
            bool(xfo.get("present", False))
            or has_frame_ancestors
        )

        if not has_clickjacking_protection:
            sec_points -= 6
            add_factor(
                "Missing Clickjacking Protection",
                -6,
                "Neither X-Frame-Options nor a CSP frame-ancestors "
                "directive was confirmed by this check.",
                "SECURITY"
            )
        else:
            add_factor(
                "Clickjacking Protection",
                0,
                "X-Frame-Options or CSP frame-ancestors protection "
                "was detected. No additional bonus is applied.",
                "SECURITY"
            )

        # Suspicious redirects
        redirects = safe_dict(
            safe_dict(redirects_data).get("redirects")
        )

        if redirects.get("hasSuspiciousRedirect", False):
            sec_points -= 30
            add_factor(
                "Insecure Redirect Downgrade",
                -30,
                "A suspicious redirect involving HTTPS-to-HTTP "
                "downgrade was detected.",
                "SECURITY"
            )

        security_score = max(0, min(100, sec_points))

        # ==========================================
        # 2. PRIVACY SCORE
        # ==========================================

        priv_points = 100

        priv_info = safe_dict(
            safe_dict(privacy_data).get("privacy")
        )

        trackers = safe_list(priv_info.get("trackers"))
        tracker_count = len(trackers)

        ad_count = safe_count(priv_info.get("adNetworkCount", 0))
        fingerprinting = priv_info.get(
            "fingerprintingDetected", False
        )

        cookie_info = safe_dict(
            safe_dict(cookies_data).get("cookies")
        )

        third_party_cookies = safe_count(
            cookie_info.get("thirdPartyCount", 0)
        )

        # Fingerprinting
        if fingerprinting is True:
            priv_points -= 35
            add_factor(
                "Canvas/Hardware Fingerprinting",
                -35,
                "Scripts perform device identification "
                "through fingerprinting techniques.",
                "PRIVACY"
            )

        # Trackers
        if tracker_count > 0:
            penalty = min(30, tracker_count * 5)
            priv_points -= penalty

            add_factor(
                f"{tracker_count} Known Trackers Detected",
                -penalty,
                f"{tracker_count} known tracking services "
                "were identified by the scanner.",
                "PRIVACY"
            )
        else:
            add_factor(
                "Zero Trackers Detected",
                0,
                "No known trackers were identified by the "
                "current scanning method. This does not "
                "guarantee the absence of tracking.",
                "PRIVACY"
            )

        # Advertising networks
        if ad_count > 0:
            penalty = min(20, ad_count * 4)
            priv_points -= penalty

            add_factor(
                f"Advertising Networks Active ({ad_count})",
                -penalty,
                f"{ad_count} advertising networks were identified.",
                "PRIVACY"
            )

        # Third-party cookies
        if third_party_cookies > 0:
            penalty = min(15, third_party_cookies * 3)
            priv_points -= penalty

            add_factor(
                "Third-Party Cookies",
                -penalty,
                f"{third_party_cookies} third-party cookies "
                "were observed by the scanner.",
                "PRIVACY"
            )

        privacy_score = max(0, min(100, priv_points))

        # ==========================================
        # 3. THREAT SCORE
        # ==========================================

        threat_info = safe_dict(
            safe_dict(threat_data).get("threat")
        )

        raw_probability = threat_info.get("probability")

        try:
            threat_prob = float(raw_probability)
            probability_available = math.isfinite(threat_prob)
        except (TypeError, ValueError, OverflowError):
            threat_prob = 0.5
            probability_available = False

        if probability_available:
            threat_prob = max(0.0, min(1.0, threat_prob))

            ml_threat_points = int(round(
                (1.0 - threat_prob) * 100
            ))

            ml_impact = ml_threat_points - 100

            add_factor(
                "ML Threat Assessment",
                ml_impact,
                f"Model threat probability: "
                f"{threat_prob * 100:.2f}%. "
                f"Initial threat score: {ml_threat_points}/100.",
                "THREAT"
            )

        else:
            # Missing or invalid model output must not be
            # interpreted as proof that a URL is safe.
            ml_threat_points = 50

            add_factor(
                "ML Threat Assessment Unavailable",
                -50,
                "A valid model probability was not provided. "
                "A neutral threat score of 50/100 is used instead "
                "of assuming zero threat.",
                "THREAT"
            )

        threat_points = ml_threat_points

        # URL-based heuristic indicators
        url_indicators = safe_list(
            safe_dict(url_data).get("indicators")
        )

        applied_indicators = set()

        for indicator in url_indicators:
            if not isinstance(indicator, dict):
                continue

            if not indicator.get("detected"):
                continue

            indicator_name = indicator.get("name")

            # Avoid applying the same heuristic more than once.
            if indicator_name in applied_indicators:
                continue

            applied_indicators.add(indicator_name)

            if indicator_name == "ip_as_host":
                threat_points -= 40
                add_factor(
                    "Direct IP Destination",
                    -40,
                    "The destination uses a numeric IP address "
                    "instead of a conventional domain name.",
                    "THREAT"
                )

            elif indicator_name == "punycode_homograph":
                threat_points -= 25
                add_factor(
                    "Lookalike Punycode Encoding",
                    -25,
                    "The domain contains punycode encoding "
                    "that may represent a homograph risk.",
                    "THREAT"
                )

            elif indicator_name == "high_entropy_domain":
                threat_points -= 15
                add_factor(
                    "High Entropy Domain",
                    -15,
                    "The domain contains unusually high "
                    "character randomness.",
                    "THREAT"
                )

        threat_score = max(0, min(100, threat_points))

        # ==========================================
        # 4. OVERALL COMPOSITE SCORE
        # ==========================================

        # 40% Security + 35% Privacy + 25% Threat

        overall = int(round(
            (0.40 * security_score)
            + (0.35 * privacy_score)
            + (0.25 * threat_score)
        ))

        if overall >= 80:
            risk_class = "SAFE"
        elif overall >= 60:
            risk_class = "LOW_RISK"
        elif overall >= 40:
            risk_class = "SUSPICIOUS"
        else:
            risk_class = "HIGH_RISK"

        return {
            "overallScore": overall,
            "securityScore": security_score,
            "privacyScore": privacy_score,
            "threatScore": threat_score,
            "riskClassification": risk_class,
            "factors": factors
        }
