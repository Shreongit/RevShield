from typing import Any, Dict, List
from app.analyzers.base import BaseAnalyzer, AnalysisContext

class HeaderAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "header_analyzer"

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        headers = {k.lower(): v for k, v in context.response_headers.items()}
        results: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        # 1. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if csp:
            is_strict = "default-src" in csp or "script-src" in csp
            has_unsafe_inline = "'unsafe-inline'" in csp
            has_unsafe_eval = "'unsafe-eval'" in csp

            if is_strict and not has_unsafe_inline:
                status = "OPTIMAL"
                impact = "LOW"
                explanation = "A strict Content Security Policy is defined, restricting sources of executable scripts, stylesheets, and objects."
            elif has_unsafe_inline or has_unsafe_eval:
                status = "SUBOPTIMAL"
                impact = "MEDIUM"
                explanation = "CSP is present but permits 'unsafe-inline' or 'unsafe-eval', which weakens defense against Cross-Site Scripting (XSS)."
            else:
                status = "OPTIMAL"
                impact = "LOW"
                explanation = "Content Security Policy is present and configured."

            results.append({
                "headerName": "Content-Security-Policy",
                "present": True,
                "value": csp[:120] + ("..." if len(csp) > 120 else ""),
                "status": status,
                "impact": impact,
                "explanation": explanation,
                "recommendation": "Maintain nonces or hashes instead of 'unsafe-inline'." if status == "SUBOPTIMAL" else None
            })
            findings.append({
                "id": "hdr-csp-present",
                "category": "SECURITY",
                "title": "Content-Security-Policy Enabled",
                "status": "PASS" if status == "OPTIMAL" else "WARN",
                "impact": impact,
                "description": explanation
            })
        else:
            results.append({
                "headerName": "Content-Security-Policy",
                "present": False,
                "value": None,
                "status": "MISSING",
                "impact": "HIGH",
                "explanation": "A Content Security Policy helps restrict browser execution of malicious scripts and unauthorized third-party embeds.",
                "recommendation": "Configure a Content-Security-Policy header such as: default-src 'self'; script-src 'self';"
            })
            findings.append({
                "id": "hdr-csp-missing",
                "category": "SECURITY",
                "title": "Missing Content-Security-Policy (CSP)",
                "status": "FAIL",
                "impact": "HIGH",
                "description": "The site does not define a Content-Security-Policy, increasing vulnerability to Cross-Site Scripting (XSS) and data injection attacks.",
                "remediation": "Add a Content-Security-Policy HTTP response header to whitelist trusted script and resource domains."
            })

        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        if hsts:
            has_subdomains = "includesubdomains" in hsts.lower()
            has_preload = "preload" in hsts.lower()
            results.append({
                "headerName": "Strict-Transport-Security",
                "present": True,
                "value": hsts,
                "status": "OPTIMAL",
                "impact": "INFO",
                "explanation": "HSTS instructs browsers to strictly communicate over HTTPS, preventing SSL stripping and downgrade attacks.",
                "recommendation": "Ensure includeSubDomains and preload are enabled for complete coverage." if not (has_subdomains and has_preload) else None
            })
            findings.append({
                "id": "hdr-hsts-present",
                "category": "SECURITY",
                "title": "Strict-Transport-Security (HSTS) Active",
                "status": "PASS",
                "impact": "INFO",
                "description": f"HSTS is properly enforcing encrypted transport ({hsts})."
            })
        else:
            results.append({
                "headerName": "Strict-Transport-Security",
                "present": False,
                "value": None,
                "status": "MISSING",
                "impact": "HIGH",
                "explanation": "Without HSTS, the first visit to the site or an unencrypted link could be intercepted by man-in-the-middle attackers.",
                "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            })
            findings.append({
                "id": "hdr-hsts-missing",
                "category": "SECURITY",
                "title": "Missing HSTS Header",
                "status": "FAIL",
                "impact": "HIGH",
                "description": "Strict-Transport-Security is not enabled, leaving connections open to protocol downgrade attacks on untrusted networks.",
                "remediation": "Enable HSTS with a max-age of at least 1 year (31536000 seconds)."
            })

        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if xfo:
            results.append({
                "headerName": "X-Frame-Options",
                "present": True,
                "value": xfo,
                "status": "OPTIMAL",
                "impact": "INFO",
                "explanation": "X-Frame-Options protects visitors from Clickjacking by preventing unauthorized framing of this page.",
            })
        else:
            # Check if CSP frame-ancestors is present
            if csp and "frame-ancestors" in csp:
                results.append({
                    "headerName": "X-Frame-Options",
                    "present": True,
                    "value": "Covered by CSP frame-ancestors",
                    "status": "OPTIMAL",
                    "impact": "INFO",
                    "explanation": "Clickjacking protection is modernly handled by CSP frame-ancestors directive.",
                })
            else:
                results.append({
                    "headerName": "X-Frame-Options",
                    "present": False,
                    "value": None,
                    "status": "MISSING",
                    "impact": "MEDIUM",
                    "explanation": "X-Frame-Options prevents the website from being embedded within an iframe on third-party sites, mitigating clickjacking attacks.",
                    "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN"
                })
                findings.append({
                    "id": "hdr-xfo-missing",
                    "category": "SECURITY",
                    "title": "Missing Clickjacking Defense (X-Frame-Options)",
                    "status": "WARN",
                    "impact": "MEDIUM",
                    "description": "The website does not restrict framing via X-Frame-Options or CSP frame-ancestors.",
                    "remediation": "Add 'X-Frame-Options: SAMEORIGIN' to response headers."
                })

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            results.append({
                "headerName": "X-Content-Type-Options",
                "present": True,
                "value": xcto,
                "status": "OPTIMAL",
                "impact": "INFO",
                "explanation": "Prevents MIME-type sniffing, stopping browsers from executing non-executable files as scripts.",
            })
        else:
            results.append({
                "headerName": "X-Content-Type-Options",
                "present": False,
                "value": xcto,
                "status": "MISSING",
                "impact": "MEDIUM",
                "explanation": "X-Content-Type-Options: nosniff forces browsers to adhere strictly to MIME types declared in Content-Type.",
                "recommendation": "Set X-Content-Type-Options: nosniff"
            })
            findings.append({
                "id": "hdr-xcto-missing",
                "category": "SECURITY",
                "title": "MIME-Type Sniffing Protection Missing",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": "Missing 'X-Content-Type-Options: nosniff' header.",
                "remediation": "Configure web server to return 'X-Content-Type-Options: nosniff'."
            })

        # 5. Referrer-Policy
        ref_pol = headers.get("referrer-policy")
        if ref_pol:
            results.append({
                "headerName": "Referrer-Policy",
                "present": True,
                "value": ref_pol,
                "status": "OPTIMAL",
                "impact": "INFO",
                "explanation": f"Controls how much referral information is sent when navigating to external websites ({ref_pol}).",
            })
        else:
            results.append({
                "headerName": "Referrer-Policy",
                "present": False,
                "value": None,
                "status": "MISSING",
                "impact": "LOW",
                "explanation": "Controls referrer leakage when users click external links or load third-party resources.",
                "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin"
            })

        # 6. Permissions-Policy
        perm_pol = headers.get("permissions-policy") or headers.get("feature-policy")
        if perm_pol:
            results.append({
                "headerName": "Permissions-Policy",
                "present": True,
                "value": perm_pol[:100],
                "status": "OPTIMAL",
                "impact": "INFO",
                "explanation": "Restricts access to browser APIs such as camera, microphone, geolocation, and payment request.",
            })
        else:
            results.append({
                "headerName": "Permissions-Policy",
                "present": False,
                "value": None,
                "status": "MISSING",
                "impact": "LOW",
                "explanation": "Restricts browser feature delegations (camera, geolocation, accelerometer).",
                "recommendation": "Define a Permissions-Policy header to restrict high-privilege device APIs."
            })

        # 7. Information Leakage Headers
        leaky = []
        if "server" in headers and any(c.isdigit() for c in headers["server"]):
            leaky.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            leaky.append(f"X-Powered-By: {headers['x-powered-by']}")
        if "x-aspnet-version" in headers:
            leaky.append(f"X-AspNet-Version: {headers['x-aspnet-version']}")

        if leaky:
            findings.append({
                "id": "hdr-info-leak",
                "category": "SECURITY",
                "title": "Server Software Fingerprint Exposed",
                "status": "WARN",
                "impact": "LOW",
                "description": f"Server response headers leak internal tech stack versions: {', '.join(leaky)}.",
                "remediation": "Disable verbose Server banners and remove X-Powered-By headers in web server configuration."
            })

        return {
            "headers": results,
            "findings": findings
        }
