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

        # ==========================================
        # 1. SECURITY SCORE (0 - 100)
        # ==========================================
        sec_points = 100

        # TLS validity
        tls_info = tls_data.get("tls_info", {})
        if not tls_info.get("valid", False):
            sec_points -= 45
            factors.append({
                "name": "Invalid or Missing TLS",
                "impactPoints": -45,
                "reason": "Traffic is not secured with a valid SSL/TLS certificate.",
                "type": "NEGATIVE"
            })
        else:
            factors.append({
                "name": "Valid TLS Certificate",
                "impactPoints": 15,
                "reason": f"Trusted certificate ({tls_info.get('issuer', 'CA')}) with {tls_info.get('protocolVersion', 'TLS')}.",
                "type": "POSITIVE"
            })

        # Headers check
        header_map = {h["headerName"]: h for h in headers_data.get("headers", [])}

        # CSP
        csp = header_map.get("Content-Security-Policy")
        if not csp or not csp.get("present"):
            sec_points -= 15
            factors.append({
                "name": "Missing CSP Header",
                "impactPoints": -15,
                "reason": "Absence of Content Security Policy increases Cross-Site Scripting exposure.",
                "type": "NEGATIVE"
            })
        elif csp.get("status") == "OPTIMAL":
            factors.append({
                "name": "Strict CSP Enabled",
                "impactPoints": 10,
                "reason": "Policy explicitly restricts untrusted code injection.",
                "type": "POSITIVE"
            })

        # HSTS
        hsts = header_map.get("Strict-Transport-Security")
        if not hsts or not hsts.get("present"):
            sec_points -= 12
            factors.append({
                "name": "Missing HSTS Header",
                "impactPoints": -12,
                "reason": "Connections are susceptible to protocol downgrade attacks.",
                "type": "NEGATIVE"
            })
        else:
            factors.append({
                "name": "HSTS Protocol Enforced",
                "impactPoints": 10,
                "reason": "Browsers strictly mandate HTTPS transport.",
                "type": "POSITIVE"
            })

        # X-Frame-Options
        xfo = header_map.get("X-Frame-Options")
        if not xfo or not xfo.get("present"):
            sec_points -= 6
        else:
            factors.append({
                "name": "Clickjacking Protection",
                "impactPoints": 5,
                "reason": "X-Frame-Options / Frame-Ancestors prevents unauthorized framing.",
                "type": "POSITIVE"
            })

        # Insecure redirects
        if redirects_data.get("redirects", {}).get("hasSuspiciousRedirect", False):
            sec_points -= 30
            factors.append({
                "name": "Insecure Redirect Downgrade",
                "impactPoints": -30,
                "reason": "Traffic is routed from HTTPS to unencrypted HTTP.",
                "type": "NEGATIVE"
            })

        security_score = max(0, min(100, sec_points))

        # ==========================================
        # 2. PRIVACY SCORE (0 - 100)
        # ==========================================
        priv_points = 100
        priv_info = privacy_data.get("privacy", {})
        trackers = priv_info.get("trackers", [])
        tracker_count = len(trackers)
        ad_count = priv_info.get("adNetworkCount", 0)
        fingerprinting = priv_info.get("fingerprintingDetected", False)
        third_party_cookies = cookies_data.get("cookies", {}).get("thirdPartyCount", 0)

        if fingerprinting:
            priv_points -= 35
            factors.append({
                "name": "Canvas/Hardware Fingerprinting",
                "impactPoints": -35,
                "reason": "Scripts perform aggressive client device identification.",
                "type": "NEGATIVE"
            })

        if tracker_count > 0:
            penalty = min(30, tracker_count * 5)
            priv_points -= penalty
            factors.append({
                "name": f"{tracker_count} Known Trackers Detected",
                "impactPoints": -penalty,
                "reason": f"Page initiates telemetry and user profiling to {tracker_count} tracking services.",
                "type": "NEGATIVE"
            })
        else:
            factors.append({
                "name": "Zero Trackers Detected",
                "impactPoints": 15,
                "reason": "No commercial tracking or profiling scripts identified.",
                "type": "POSITIVE"
            })

        if ad_count > 0:
            penalty = min(20, ad_count * 4)
            priv_points -= penalty
            factors.append({
                "name": f"Advertising Networks Active ({ad_count})",
                "impactPoints": -penalty,
                "reason": f"Advertising SDKs loaded ({ad_count} networks).",
                "type": "NEGATIVE"
            })

        if third_party_cookies > 0:
            penalty = min(15, third_party_cookies * 3)
            priv_points -= penalty
            factors.append({
                "name": "Third-Party Cookies",
                "impactPoints": -penalty,
                "reason": f"{third_party_cookies} cookies stored on external domains.",
                "type": "NEGATIVE"
            })

        privacy_score = max(0, min(100, priv_points))

        # ==========================================
        # 3. THREAT SCORE (0 - 100)
        # ==========================================
        # 100 means completely safe, 0 means high threat
        threat_info = threat_data.get("threat", {})
        threat_prob = threat_info.get("probability", 0.0)

        # ML Threat Probability
        ml_threat_points = int((1.0 - threat_prob) * 100)

        # Heuristic adjustments
        url_indicators = url_data.get("indicators", [])
        for ind in url_indicators:
            if ind.get("detected"):
                if ind["name"] == "ip_as_host":
                    ml_threat_points -= 40
                    factors.append({
                        "name": "Direct IP Destination",
                        "impactPoints": -40,
                        "reason": "Host uses numeric IP rather than verifiable domain.",
                        "type": "NEGATIVE"
                    })
                elif ind["name"] == "punycode_homograph":
                    ml_threat_points -= 25
                    factors.append({
                        "name": "Lookalike Punycode Encoding",
                        "impactPoints": -25,
                        "reason": "Domain employs Unicode homograph representations.",
                        "type": "NEGATIVE"
                    })
                elif ind["name"] == "high_entropy_domain":
                    ml_threat_points -= 15

        threat_score = max(0, min(100, ml_threat_points))

        # ==========================================
        # 4. OVERALL COMPOSITE SCORE (0 - 100)
        # ==========================================
        # Weighted formula: 40% Security + 35% Privacy + 25% Threat
        overall = int(round((0.40 * security_score) + (0.35 * privacy_score) + (0.25 * threat_score)))

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
