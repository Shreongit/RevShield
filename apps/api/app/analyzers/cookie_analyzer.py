from http.cookies import SimpleCookie
from typing import Any, Dict, List
from app.analyzers.base import BaseAnalyzer, AnalysisContext

KNOWN_COOKIE_PURPOSES = {
    "_ga": "Google Analytics visitor identifier (Analytics)",
    "_gid": "Google Analytics 24-hour session distinction (Analytics)",
    "_gat": "Google Analytics request throttle token (Analytics)",
    "_fbp": "Meta/Facebook ad tracking pixel cookie (Advertising)",
    "_clck": "Microsoft Clarity user identifier (Session Replay)",
    "_clsk": "Microsoft Clarity session recorder state (Session Replay)",
    "csrftoken": "Cross-Site Request Forgery protection (Security)",
    "sessionid": "Session authentication state (Essential)",
    "token": "Authentication token (Essential)",
    "remember_me": "Persistent session identifier (Essential)",
    "theme": "User interface display preference (Functional)"
}

class CookieAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "cookie_analyzer"

    def _estimate_purpose(self, cookie_name: str) -> str:
        name_lower = cookie_name.lower()
        for key, desc in KNOWN_COOKIE_PURPOSES.items():
            if key in name_lower:
                return desc
        if "sess" in name_lower or "auth" in name_lower or "jwt" in name_lower:
            return "Authentication & Session Management"
        if "track" in name_lower or "stat" in name_lower or "metric" in name_lower:
            return "Visitor Metrics & Telemetry"
        if "opt" in name_lower or "consent" in name_lower:
            return "Privacy & Consent Storage"
        return "Site Functionality & State"

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        base_domain = context.domain.lower()

        # Parse Set-Cookie header lines
        cookie_items: List[Dict[str, Any]] = []
        set_cookie_raw = context.response_headers.get("set-cookie") or ""

        # SimpleCookie handles standard cookie formatting
        if set_cookie_raw:
            try:
                cookie_jar = SimpleCookie()
                cookie_jar.load(set_cookie_raw)
                for name, morsel in cookie_jar.items():
                    c_domain = (morsel.get("domain") or base_domain).lstrip(".").lower()
                    c_path = morsel.get("path") or "/"
                    c_secure = bool(morsel.get("secure"))
                    c_httponly = bool(morsel.get("httponly"))
                    c_samesite = morsel.get("samesite") or "Unset"
                    c_expires = morsel.get("expires") or morsel.get("max-age") or None
                    is_third_party = not (c_domain == base_domain or base_domain.endswith(c_domain))
                    is_persistent = bool(c_expires)

                    cookie_items.append({
                        "name": name,
                        "domain": c_domain,
                        "path": c_path,
                        "isSecure": c_secure,
                        "isHttpOnly": c_httponly,
                        "sameSite": c_samesite if c_samesite in ("Strict", "Lax", "None") else "Unset",
                        "isThirdParty": is_third_party,
                        "isPersistent": is_persistent,
                        "expires": str(c_expires) if c_expires else None,
                        "estimatedPurpose": self._estimate_purpose(name)
                    })
            except Exception:
                pass

        # Also merge any response_cookies passed from context
        for c in context.response_cookies:
            if not any(item["name"] == c.get("name") for item in cookie_items):
                name = c.get("name", "unknown")
                c_domain = (c.get("domain") or base_domain).lstrip(".").lower()
                cookie_items.append({
                    "name": name,
                    "domain": c_domain,
                    "path": c.get("path", "/"),
                    "isSecure": bool(c.get("secure", False)),
                    "isHttpOnly": bool(c.get("httponly", False)),
                    "sameSite": c.get("sameSite", "Unset"),
                    "isThirdParty": not (c_domain == base_domain or base_domain.endswith(c_domain)),
                    "isPersistent": bool(c.get("expires")),
                    "expires": str(c.get("expires")) if c.get("expires") else None,
                    "estimatedPurpose": self._estimate_purpose(name)
                })

        total = len(cookie_items)
        first_party = sum(1 for c in cookie_items if not c["isThirdParty"])
        third_party = sum(1 for c in cookie_items if c["isThirdParty"])
        session = sum(1 for c in cookie_items if not c["isPersistent"])
        persistent = sum(1 for c in cookie_items if c["isPersistent"])
        insecure = sum(1 for c in cookie_items if not c["isSecure"])

        # Generate findings
        if insecure > 0 and context.normalized_url.startswith("https://"):
            findings.append({
                "id": "cookie-insecure",
                "category": "COOKIES",
                "title": f"Insecure Cookies Detected ({insecure} cookies)",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": f"{insecure} cookies are missing the 'Secure' attribute, allowing transmission across unencrypted connections.",
                "remediation": "Add the 'Secure' attribute to all Set-Cookie headers."
            })

        missing_samesite = sum(1 for c in cookie_items if c["sameSite"] == "Unset")
        if missing_samesite > 0:
            findings.append({
                "id": "cookie-missing-samesite",
                "category": "COOKIES",
                "title": f"Cookies Missing SameSite ({missing_samesite} cookies)",
                "status": "WARN",
                "impact": "LOW",
                "description": "Cookies without an explicit SameSite attribute default to browser heuristics, risking Cross-Site Request Forgery (CSRF).",
                "remediation": "Explicitly set SameSite=Lax or SameSite=Strict."
            })

        if third_party > 0:
            findings.append({
                "id": "cookie-third-party",
                "category": "COOKIES",
                "title": f"Third-Party Tracking Cookies ({third_party} cookies)",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": f"The website sets {third_party} third-party cookies used for cross-site tracking and profiling.",
            })

        return {
            "cookies": {
                "totalCookies": total,
                "firstPartyCount": first_party,
                "thirdPartyCount": third_party,
                "sessionCount": session,
                "persistentCount": persistent,
                "insecureCount": insecure,
                "items": cookie_items
            },
            "findings": findings
        }
