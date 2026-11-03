
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional, Tuple

from urllib.parse import urlparse

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

        if any(
            token in name_lower
            for token in ("sess", "auth", "jwt")
        ):
            return "Authentication & Session Management"

        if any(
            token in name_lower
            for token in ("track", "stat", "metric")
        ):
            return "Visitor Metrics & Telemetry"

        if any(
            token in name_lower
            for token in ("opt", "consent")
        ):
            return "Privacy & Consent Storage"

        return "Site Functionality & State"

    @staticmethod
    def _normalize_domain(domain: Optional[str]) -> str:

        if not domain:
            return ""

        return domain.strip().lstrip(".").rstrip(".").lower()

    @staticmethod
    def _domain_matches(host: str, cookie_domain: str) -> bool:

        host = host.lower().rstrip(".")
        cookie_domain = cookie_domain.lower().lstrip(".").rstrip(".")

        return (
            host == cookie_domain
            or host.endswith("." + cookie_domain)
        )

    @staticmethod
    def _is_persistent(morsel: Any) -> bool:

        return bool(
            morsel.get("expires")
            or morsel.get("max-age")
        )

    def _build_cookie_item(
        self,
        name: str,
        attributes: Dict[str, Any],
        base_domain: str
    ) -> Dict[str, Any]:

        cookie_domain = self._normalize_domain(
            attributes.get("domain") or base_domain
        )

        path = attributes.get("path") or "/"

        secure = bool(attributes.get("secure", False))

        httponly = bool(attributes.get("httponly", False))

        same_site = attributes.get("samesite") or "Unset"

        same_site = str(same_site).capitalize()

        if same_site not in ("Strict", "Lax", "None"):
            same_site = "Unset"

        expires = (
            attributes.get("expires")
            or attributes.get("max-age")
            or None
        )

        return {
            "name": name,
            "domain": cookie_domain,
            "path": path,
            "isSecure": secure,
            "isHttpOnly": httponly,
            "sameSite": same_site,
            "isThirdParty": not self._domain_matches(
                base_domain,
                cookie_domain
            ),
            "isPersistent": bool(expires),
            "expires": str(expires) if expires else None,
            "estimatedPurpose": self._estimate_purpose(name)
        }

    @staticmethod
    def _cookie_key(cookie: Dict[str, Any]) -> Tuple[str, str, str]:

        return (
            cookie["name"],
            cookie["domain"],
            cookie["path"]
        )

    async def analyze(
        self,
        context: AnalysisContext
    ) -> Dict[str, Any]:

        findings: List[Dict[str, Any]] = []

        base_domain = self._normalize_domain(
            urlparse(context.normalized_url).hostname
            or context.domain
        )

        cookie_items: List[Dict[str, Any]] = []

        seen_keys = set()

        # ==========================================
        # 1. PARSE SET-COOKIE RESPONSE HEADER
        # ==========================================

        set_cookie_raw = (
            context.response_headers.get("set-cookie")
            or context.response_headers.get("Set-Cookie")
            or ""
        )

        if isinstance(set_cookie_raw, str) and set_cookie_raw:

            try:
                cookie_jar = SimpleCookie()
                cookie_jar.load(set_cookie_raw)

                for name, morsel in cookie_jar.items():

                    item = self._build_cookie_item(
                        name,
                        {
                            "domain": morsel.get("domain"),
                            "path": morsel.get("path"),
                            "secure": morsel.get("secure"),
                            "httponly": morsel.get("httponly"),
                            "samesite": morsel.get("samesite"),
                            "expires": morsel.get("expires"),
                            "max-age": morsel.get("max-age")
                        },
                        base_domain
                    )

                    key = self._cookie_key(item)

                    if key not in seen_keys:
                        seen_keys.add(key)
                        cookie_items.append(item)

            except Exception:
                findings.append({
                    "id": "cookie-parse-warning",
                    "category": "COOKIES",
                    "title": "Cookie Header Parsing Incomplete",
                    "status": "WARN",
                    "impact": "LOW",
                    "description": (
                        "The Set-Cookie response header could not "
                        "be completely parsed."
                    ),
                    "remediation": (
                        "Review the raw Set-Cookie response headers."
                    )
                })

        # ==========================================
        # 2. MERGE RESPONSE COOKIE DATA
        # ==========================================

        for cookie in context.response_cookies:

            name = cookie.get("name")

            if not name:
                continue

            item = self._build_cookie_item(
                name,
                {
                    "domain": cookie.get("domain"),
                    "path": cookie.get("path"),
                    "secure": cookie.get("secure"),
                    "httponly": cookie.get("httponly"),
                    "samesite": (
                        cookie.get("samesite")
                        or cookie.get("sameSite")
                    ),
                    "expires": cookie.get("expires"),
                    "max-age": cookie.get("max-age")
                },
                base_domain
            )

            key = self._cookie_key(item)

            if key not in seen_keys:
                seen_keys.add(key)
                cookie_items.append(item)

        # ==========================================
        # 3. COOKIE STATISTICS
        # ==========================================

        total = len(cookie_items)

        first_party = sum(
            1 for c in cookie_items
            if not c["isThirdParty"]
        )

        third_party = sum(
            1 for c in cookie_items
            if c["isThirdParty"]
        )

        session = sum(
            1 for c in cookie_items
            if not c["isPersistent"]
        )

        persistent = sum(
            1 for c in cookie_items
            if c["isPersistent"]
        )

        insecure = sum(
            1 for c in cookie_items
            if not c["isSecure"]
        )

        missing_httponly = sum(
            1 for c in cookie_items
            if not c["isHttpOnly"]
        )

        missing_samesite = sum(
            1 for c in cookie_items
            if c["sameSite"] == "Unset"
        )

        # ==========================================
        # 4. SECURITY FINDINGS
        # ==========================================

        if insecure > 0 and context.normalized_url.startswith("https://"):

            findings.append({
                "id": "cookie-insecure",
                "category": "COOKIES",
                "title": f"Insecure Cookies Detected ({insecure} cookies)",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    f"{insecure} observed cookies are missing "
                    "the Secure attribute."
                ),
                "remediation": (
                    "Add the Secure attribute to cookies that "
                    "should only be transmitted over HTTPS."
                )
            })

        if missing_httponly > 0:

            findings.append({
                "id": "cookie-missing-httponly",
                "category": "COOKIES",
                "title": f"Cookies Missing HttpOnly ({missing_httponly})",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    "Some observed cookies are accessible to "
                    "JavaScript because they lack HttpOnly."
                ),
                "remediation": (
                    "Set HttpOnly on session and authentication "
                    "cookies that do not require JavaScript access."
                )
            })

        if missing_samesite > 0:

            findings.append({
                "id": "cookie-missing-samesite",
                "category": "COOKIES",
                "title": f"Cookies Missing SameSite ({missing_samesite})",
                "status": "WARN",
                "impact": "LOW",
                "description": (
                    "Some observed cookies do not explicitly "
                    "declare a SameSite attribute."
                ),
                "remediation": (
                    "Explicitly configure SameSite=Lax or "
                    "SameSite=Strict where appropriate."
                )
            })

        if third_party > 0:

            findings.append({
                "id": "cookie-third-party",
                "category": "COOKIES",
                "title": f"Cross-Domain Cookie Scope ({third_party})",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    f"{third_party} observed cookies specify a "
                    "domain outside the scanned hostname's "
                    "domain scope. These may be rejected by browsers."
                ),
                "remediation": (
                    "Review cookie Domain attributes and use "
                    "the narrowest appropriate domain scope."
                )
            })

        # ==========================================
        # 5. RETURN RESULTS
        # ==========================================

        return {
            "cookies": {
                "totalCookies": total,
                "firstPartyCount": first_party,
                "thirdPartyCount": third_party,
                "sessionCount": session,
                "persistentCount": persistent,
                "insecureCount": insecure,
                "items": cookie_items,

                "missingHttpOnlyCount": missing_httponly,
                "missingSameSiteCount": missing_samesite,

                "observationScope": "HTTP_RESPONSE_COOKIES",

                "coverageNotice": (
                    "Cookie results represent cookies observed "
                    "in HTTP response headers and supplied "
                    "response cookie data. JavaScript-created "
                    "cookies, browser storage and cookies set "
                    "during unobserved browser interactions "
                    "are not included."
                )
            },
            "findings": findings
        }
