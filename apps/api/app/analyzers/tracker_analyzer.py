
from collections import defaultdict
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.analyzers.base import BaseAnalyzer, AnalysisContext


TRACKER_SIGNATURES = [
    {"pattern": "google-analytics.com", "category": "ANALYTICS", "owner": "Google LLC", "desc": "Web traffic measurement and visitor behavior telemetry.", "impact": "MEDIUM"},
    {"pattern": "googletagmanager.com", "category": "ANALYTICS", "owner": "Google LLC", "desc": "Tag management container system.", "impact": "LOW"},
    {"pattern": "doubleclick.net", "category": "ADVERTISING", "owner": "Google LLC", "desc": "Programmatic display advertising network.", "impact": "HIGH"},
    {"pattern": "googlesyndication.com", "category": "ADVERTISING", "owner": "Google LLC", "desc": "AdSense ad distribution and monetization.", "impact": "HIGH"},
    {"pattern": "googleadservices.com", "category": "ADVERTISING", "owner": "Google LLC", "desc": "Google Ads conversion and retargeting tracking.", "impact": "HIGH"},
    {"pattern": "facebook.net", "category": "SOCIAL", "owner": "Meta Platforms", "desc": "Facebook Pixel, SDK, and cross-site social tracking.", "impact": "HIGH"},
    {"pattern": "connect.facebook.net", "category": "SOCIAL", "owner": "Meta Platforms", "desc": "Meta social tracking and graph connectors.", "impact": "HIGH"},
    {"pattern": "hotjar.com", "category": "SESSION_REPLAY", "owner": "Hotjar Ltd", "desc": "Session recording, click maps, and user behavior heatmaps.", "impact": "HIGH"},
    {"pattern": "clarity.ms", "category": "SESSION_REPLAY", "owner": "Microsoft", "desc": "Session replay and behavioral click telemetry.", "impact": "HIGH"},
    {"pattern": "criteo.com", "category": "ADVERTISING", "owner": "Criteo SA", "desc": "Behavioral retargeting and commercial tracking.", "impact": "HIGH"},
    {"pattern": "taboola.com", "category": "ADVERTISING", "owner": "Taboola Inc", "desc": "Content recommendation and sponsored advertising.", "impact": "HIGH"},
    {"pattern": "outbrain.com", "category": "ADVERTISING", "owner": "Outbrain Inc", "desc": "Native sponsored content distribution network.", "impact": "HIGH"},
    {"pattern": "tiktok.com", "category": "SOCIAL", "owner": "ByteDance Ltd", "desc": "TikTok analytics pixel and conversion tracking.", "impact": "HIGH"},
    {"pattern": "licdn.com", "category": "SOCIAL", "owner": "Microsoft LinkedIn", "desc": "LinkedIn Insight conversion tracking tag.", "impact": "MEDIUM"},
    {"pattern": "segment.io", "category": "TELEMETRY", "owner": "Twilio Segment", "desc": "Customer data platform and event aggregation.", "impact": "MEDIUM"},
    {"pattern": "mixpanel.com", "category": "ANALYTICS", "owner": "Mixpanel Inc", "desc": "Product analytics and user action tracking.", "impact": "MEDIUM"},
    {"pattern": "amplitude.com", "category": "ANALYTICS", "owner": "Amplitude Inc", "desc": "Product behavioral analytics engine.", "impact": "MEDIUM"},
    {"pattern": "fingerprintjs.com", "category": "FINGERPRINTING", "owner": "FingerprintJS Inc", "desc": "Device and browser fingerprinting engine.", "impact": "CRITICAL"},
    {"pattern": "fpnpmcdn.net", "category": "FINGERPRINTING", "owner": "FingerprintJS Inc", "desc": "Fingerprint CDN payload host.", "impact": "CRITICAL"},
    {"pattern": "adnxs.com", "category": "ADVERTISING", "owner": "Xandr / Microsoft", "desc": "Digital ad exchange and real-time bidding.", "impact": "HIGH"},
    {"pattern": "rubiconproject.com", "category": "ADVERTISING", "owner": "Magnite Inc", "desc": "Supply-side automated ad platform.", "impact": "HIGH"},
    {"pattern": "pubmatic.com", "category": "ADVERTISING", "owner": "PubMatic Inc", "desc": "Digital advertising yield and targeting engine.", "impact": "HIGH"},
    {"pattern": "openx.net", "category": "ADVERTISING", "owner": "OpenX Software", "desc": "Programmatic ad marketplace.", "impact": "HIGH"},
    {"pattern": "amazon-adsystem.com", "category": "ADVERTISING", "owner": "Amazon.com", "desc": "Amazon advertising network.", "impact": "HIGH"},
    {"pattern": "sentry.io", "category": "TELEMETRY", "owner": "Functional Software", "desc": "Application performance and error telemetry.", "impact": "LOW"},
    {"pattern": "datadoghq.com", "category": "TELEMETRY", "owner": "Datadog Inc", "desc": "Real user monitoring and synthetic traces.", "impact": "LOW"},
    {"pattern": "coinhive.com", "category": "CRYPTOMINING", "owner": "Coinhive", "desc": "Browser-based cryptocurrency miner.", "impact": "CRITICAL"}
]


class TrackerAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "tracker_analyzer"

    @staticmethod
    def _is_same_domain(hostname: str, base_domain: str) -> bool:

        hostname = hostname.lower().rstrip(".")
        base_domain = base_domain.lower().rstrip(".")

        return (
            hostname == base_domain
            or hostname.endswith("." + base_domain)
        )

    @staticmethod
    def _extract_resources_from_html(
        html_content: str,
        page_url: str
    ) -> List[str]:

        if not html_content:
            return []

        resources = set()

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # External scripts
            for tag in soup.find_all("script", src=True):
                resources.add(tag["src"])

            # Embedded frames
            for tag in soup.find_all(["iframe", "frame"], src=True):
                resources.add(tag["src"])

            # Images and tracking pixels
            for tag in soup.find_all("img", src=True):
                resources.add(tag["src"])

            # Stylesheets, icons and preload resources
            for tag in soup.find_all("link", href=True):
                resources.add(tag["href"])

            # Media resources
            for tag in soup.find_all(["audio", "video", "source", "track"]):
                for attr in ("src", "poster"):
                    if tag.get(attr):
                        resources.add(tag[attr])

                # Responsive image/media references
                if tag.get("srcset"):
                    for candidate in tag["srcset"].split(","):
                        parts = candidate.strip().split()

                        if parts:
                            resources.add(parts[0])

        except Exception:
            return []

        normalized_resources = []

        for resource in resources:

            if not isinstance(resource, str):
                continue

            resource = resource.strip()

            if not resource:
                continue

            absolute_url = urljoin(page_url, resource)

            parsed = urlparse(absolute_url)

            if parsed.scheme.lower() not in ("http", "https"):
                continue

            if not parsed.hostname:
                continue

            normalized_resources.append(absolute_url)

        return sorted(set(normalized_resources))

    @staticmethod
    def _match_tracker(hostname: str):

        hostname = hostname.lower().rstrip(".")

        for signature in TRACKER_SIGNATURES:

            pattern = signature["pattern"].lower()

            if (
                hostname == pattern
                or hostname.endswith("." + pattern)
            ):
                return signature

        return None

    async def analyze(
        self,
        context: AnalysisContext
    ) -> Dict[str, Any]:

        findings: List[Dict[str, Any]] = []

        base_domain = context.domain.lower().rstrip(".")

        # ==========================================
        # 1. EXTRACT RESOURCE REFERENCES
        # ==========================================

        candidate_urls: Set[str] = set()

        if context.response_body:

            extracted = self._extract_resources_from_html(
                context.response_body,
                context.normalized_url
            )

            candidate_urls.update(extracted)

        # Include externally supplied resource references.
        # These are not assumed to be complete browser traffic.
        for resource in context.third_party_resources or []:

            if not isinstance(resource, str):
                continue

            absolute_url = urljoin(
                context.normalized_url,
                resource.strip()
            )

            parsed = urlparse(absolute_url)

            if (
                parsed.scheme.lower() in ("http", "https")
                and parsed.hostname
            ):
                candidate_urls.add(absolute_url)

        # ==========================================
        # 2. CLASSIFY THIRD-PARTY RESOURCES
        # ==========================================

        third_party_hosts: Set[str] = set()

        tracker_hits = defaultdict(lambda: {
            "count": 0,
            "category": "UNKNOWN",
            "owner": "Unknown",
            "impact": "LOW",
            "desc": "",
            "samples": []
        })

        categories_seen: Set[str] = set()

        fingerprinting_detected = False
        ad_network_count = 0

        for url_str in sorted(candidate_urls):

            try:
                parsed = urlparse(url_str)

                hostname = (
                    parsed.hostname or ""
                ).lower().rstrip(".")

                if not hostname:
                    continue

                if self._is_same_domain(hostname, base_domain):
                    continue

                third_party_hosts.add(hostname)

                signature = self._match_tracker(hostname)

                if not signature:
                    continue

                category = signature["category"]

                categories_seen.add(category)

                if category == "FINGERPRINTING":
                    fingerprinting_detected = True

                if category == "ADVERTISING":
                    ad_network_count += 1

                data = tracker_hits[hostname]

                data["count"] += 1
                data["category"] = category
                data["owner"] = signature["owner"]
                data["impact"] = signature["impact"]
                data["desc"] = signature["desc"]

                if len(data["samples"]) < 3:
                    data["samples"].append(url_str[:200])

            except Exception:
                continue

        # ==========================================
        # 3. FORMAT TRACKER RESULTS
        # ==========================================

        detected_trackers = []

        for domain, data in sorted(tracker_hits.items()):

            detected_trackers.append({
                "domain": domain,
                "owner": data["owner"],
                "category": data["category"],
                "requestCount": data["count"],
                "impact": data["impact"],
                "description": data["desc"],
                "sampleUrls": data["samples"]
            })

        tracker_count = len(detected_trackers)

        # ==========================================
        # 4. PRIVACY FINDINGS
        # ==========================================

        if fingerprinting_detected:

            findings.append({
                "id": "trk-fingerprinting",
                "category": "PRIVACY",
                "title": "Fingerprinting-Related Resource Detected",
                "status": "WARN",
                "impact": "HIGH",
                "description": (
                    "A resource associated with a known "
                    "fingerprinting service was referenced "
                    "in the inspected page resources. "
                    "Actual fingerprinting execution was "
                    "not independently verified."
                ),
                "remediation": (
                    "Review the detected service and remove "
                    "unnecessary device fingerprinting."
                )
            })

        if ad_network_count > 3:

            findings.append({
                "id": "trk-heavy-ads",
                "category": "PRIVACY",
                "title": (
                    f"Extensive Advertising Footprint "
                    f"({ad_network_count} resource references)"
                ),
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    "Multiple known advertising network "
                    "resources were referenced in the "
                    "inspected page."
                ),
                "remediation": (
                    "Review advertising integrations and "
                    "limit unnecessary third-party tracking."
                )
            })

        if tracker_count == 0 and len(third_party_hosts) == 0:

            findings.append({
                "id": "trk-clean-privacy",
                "category": "PRIVACY",
                "title": "No Third-Party Resources Detected",
                "status": "PASS",
                "impact": "INFO",
                "description": (
                    "No third-party resource references were "
                    "identified in the inspected HTML."
                )
            })

        # ==========================================
        # 5. RETURN STRUCTURED RESULTS
        # ==========================================

        return {
            "privacy": {
                # Legacy field retained for API compatibility.
                # This represents unique referenced URLs, not
                # actual observed browser network requests.
                "totalThirdPartyRequests": len(
                    candidate_urls.intersection(
                        candidate_urls
                    )
                ) if False else sum(
                    1 for url in candidate_urls
                    if (
                        (urlparse(url).hostname or "").lower().rstrip(".")
                        and not self._is_same_domain(
                            (urlparse(url).hostname or "").lower().rstrip("."),
                            base_domain
                        )
                    )
                ),

                "thirdPartyHostCount": len(third_party_hosts),

                "trackerCount": tracker_count,

                "adNetworkCount": ad_network_count,

                "fingerprintingDetected": fingerprinting_detected,

                "trackers": detected_trackers,

                "categoriesEncountered": sorted(categories_seen),

                "observationScope": "STATIC_HTML_RESOURCE_REFERENCES",

                "coverageNotice": (
                    "Results are based on resource URLs extracted "
                    "from the fetched HTML and supplied resource "
                    "references. They do not represent complete "
                    "browser network traffic. Dynamically generated "
                    "requests, JavaScript execution, service workers "
                    "and resources loaded after page interaction "
                    "may not be observed."
                )
            },
            "findings": findings
        }
