from collections import defaultdict
from urllib.parse import urlparse
from typing import Any, Dict, List, Set
from bs4 import BeautifulSoup
from app.analyzers.base import BaseAnalyzer, AnalysisContext

TRACKER_SIGNATURES = [
    {"pattern": "google-analytics.com", "category": "ANALYTICS", "owner": "Google LLC", "desc": "Web traffic measurement & visitor behavior telemetry.", "impact": "MEDIUM"},
    {"pattern": "googletagmanager.com", "category": "ANALYTICS", "owner": "Google LLC", "desc": "Tag management container system.", "impact": "LOW"},
    {"pattern": "doubleclick.net", "category": "ADVERTISING", "owner": "Google LLC", "desc": "Programmatic display advertising network.", "impact": "HIGH"},
    {"pattern": "googlesyndication.com", "category": "ADVERTISING", "owner": "Google LLC", "desc": "AdSense ad distribution and monetization.", "impact": "HIGH"},
    {"pattern": "googleadservices.com", "category": "ADVERTISING", "owner": "Google LLC", "desc": "Google Ads conversion & retargeting tracking.", "impact": "HIGH"},
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
    {"pattern": "fingerprintjs.com", "category": "FINGERPRINTING", "owner": "FingerprintJS Inc", "desc": "Device & browser canvas/audio fingerprinting engine.", "impact": "CRITICAL"},
    {"pattern": "fpnpmcdn.net", "category": "FINGERPRINTING", "owner": "FingerprintJS Inc", "desc": "Fingerprint CDN payload host.", "impact": "CRITICAL"},
    {"pattern": "adnxs.com", "category": "ADVERTISING", "owner": "Xandr / Microsoft", "desc": "Digital ad exchange and real-time bidding.", "impact": "HIGH"},
    {"pattern": "rubiconproject.com", "category": "ADVERTISING", "owner": "Magnite Inc", "desc": "Supply-side automated ad platform.", "impact": "HIGH"},
    {"pattern": "pubmatic.com", "category": "ADVERTISING", "owner": "PubMatic Inc", "desc": "Digital advertising yield and targeting engine.", "impact": "HIGH"},
    {"pattern": "openx.net", "category": "ADVERTISING", "owner": "OpenX Software", "desc": "Programmatic ad marketplace.", "impact": "HIGH"},
    {"pattern": "amazon-adsystem.com", "category": "ADVERTISING", "owner": "Amazon.com", "desc": "Amazon Sponsored Products and display ad network.", "impact": "HIGH"},
    {"pattern": "sentry.io", "category": "TELEMETRY", "owner": "Functional Software", "desc": "Application performance and error telemetry.", "impact": "LOW"},
    {"pattern": "datadoghq.com", "category": "TELEMETRY", "owner": "Datadog Inc", "desc": "Real user monitoring and synthetic traces.", "impact": "LOW"},
    {"pattern": "coinhive.com", "category": "CRYPTOMINING", "owner": "Coinhive", "desc": "Browser-based cryptocurrency miner.", "impact": "CRITICAL"}
]

class TrackerAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "tracker_analyzer"

    def _extract_resources_from_html(self, html_content: str, base_domain: str) -> List[str]:
        urls: List[str] = []
        if not html_content:
            return urls

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            # Scripts
            for tag in soup.find_all("script", src=True):
                urls.append(tag["src"])
            # Iframes
            for tag in soup.find_all("iframe", src=True):
                urls.append(tag["src"])
            # Images & tracking pixels
            for tag in soup.find_all("img", src=True):
                urls.append(tag["src"])
            # Links / stylesheets / preloads
            for tag in soup.find_all("link", href=True):
                urls.append(tag["href"])
        except Exception:
            pass

        return urls

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        base_domain = context.domain.lower()

        # Gather resource URLs from parsed HTML + any recorded network requests
        candidate_urls: Set[str] = set(context.third_party_resources or [])
        if context.response_body:
            extracted = self._extract_resources_from_html(context.response_body, base_domain)
            candidate_urls.update(extracted)

        third_party_count = 0
        tracker_hits: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
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

        for url_str in candidate_urls:
            try:
                parsed = urlparse(url_str)
                hostname = (parsed.hostname or "").lower()
                if not hostname:
                    continue

                if not (hostname == base_domain or hostname.endswith("." + base_domain)):
                    third_party_count += 1

                    # Match against tracker signatures
                    matched = False
                    for sig in TRACKER_SIGNATURES:
                        if sig["pattern"] in hostname or sig["pattern"] in url_str.lower():
                            matched = True
                            cat = sig["category"]
                            categories_seen.add(cat)
                            if cat == "FINGERPRINTING":
                                fingerprinting_detected = True
                            if cat == "ADVERTISING":
                                ad_network_count += 1

                            tracker_hits[hostname]["count"] += 1
                            tracker_hits[hostname]["category"] = cat
                            tracker_hits[hostname]["owner"] = sig["owner"]
                            tracker_hits[hostname]["impact"] = sig["impact"]
                            tracker_hits[hostname]["desc"] = sig["desc"]
                            if len(tracker_hits[hostname]["samples"]) < 3:
                                tracker_hits[hostname]["samples"].append(url_str[:120])
                            break

                    if not matched and (hostname != base_domain and not hostname.endswith("." + base_domain)):
                        # Generic third-party domain
                        if hostname not in tracker_hits:
                            tracker_hits[hostname]["count"] += 1
                            tracker_hits[hostname]["category"] = "CONTENT_DELIVERY"
                            tracker_hits[hostname]["owner"] = "Third-Party Service"
                            tracker_hits[hostname]["impact"] = "LOW"
                            tracker_hits[hostname]["desc"] = "Third-party host resource request."
                        else:
                            tracker_hits[hostname]["count"] += 1
            except Exception:
                continue

        # Format structured trackers list
        detected_trackers: List[Dict[str, Any]] = []
        for domain, data in tracker_hits.items():
            if data["category"] != "CONTENT_DELIVERY":
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

        # Generate findings
        if fingerprinting_detected:
            findings.append({
                "id": "trk-fingerprinting",
                "category": "PRIVACY",
                "title": "Device Fingerprinting Detected",
                "status": "FAIL",
                "impact": "CRITICAL",
                "description": "The site loads scripts designed to generate unique hardware/canvas device fingerprints across sessions.",
                "remediation": "Remove intrusive client fingerprinting libraries."
            })

        if ad_network_count > 3:
            findings.append({
                "id": "trk-heavy-ads",
                "category": "PRIVACY",
                "title": f"Extensive Advertising Footprint ({ad_network_count} networks)",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": f"Multiple advertising networks detected, creating potential ad-tech tracking and telemetry exposure.",
            })
        elif tracker_count == 0 and third_party_count == 0:
            findings.append({
                "id": "trk-clean-privacy",
                "category": "PRIVACY",
                "title": "Zero Trackers Detected",
                "status": "PASS",
                "impact": "INFO",
                "description": "No known third-party tracking scripts, analytics pixels, or advertising beacons were detected on this page."
            })

        return {
            "privacy": {
                "totalThirdPartyRequests": third_party_count,
                "trackerCount": tracker_count,
                "adNetworkCount": ad_network_count,
                "fingerprintingDetected": fingerprinting_detected,
                "trackers": detected_trackers,
                "categoriesEncountered": list(categories_seen)
            },
            "findings": findings
        }
