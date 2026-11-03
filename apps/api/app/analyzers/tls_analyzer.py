
import asyncio
import datetime
import hashlib
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from app.analyzers.base import BaseAnalyzer, AnalysisContext


class _MixedContentParser(HTMLParser):
    """Collect HTTP resources referenced by static HTML."""

    RESOURCE_ATTRIBUTES = {
        "script": ("src",),
        "img": ("src", "srcset"),
        "iframe": ("src",),
        "audio": ("src",),
        "video": ("src", "poster"),
        "source": ("src", "srcset"),
        "link": ("href",),
    }

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.mixed_resources = set()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attributes = dict(attrs)

        for attribute in self.RESOURCE_ATTRIBUTES.get(tag.lower(), ()):
            value = attributes.get(attribute)

            if not value:
                continue

            candidates = []

            if attribute == "srcset":
                candidates = [
                    item.strip().split()[0]
                    for item in value.split(",")
                    if item.strip()
                ]
            else:
                candidates = [value.strip()]

            for candidate in candidates:
                absolute_url = urljoin(self.base_url, candidate)
                parsed = urlparse(absolute_url)

                if parsed.scheme.lower() == "http":
                    self.mixed_resources.add(absolute_url)


class TLSAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "tls_analyzer"

    @staticmethod
    def _open_verified_connection(
        hostname: str,
        port: int,
        context: ssl.SSLContext,
    ) -> Dict[str, Any]:
        """Perform a TLS handshake with mandatory certificate verification."""

        with socket.create_connection(
            (hostname, port),
            timeout=7.0,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:

                cert = tls_socket.getpeercert()

                return {
                    "success": True,
                    "cert": cert,
                    "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher(),
                }

    @staticmethod
    def _probe_unverified_connection(
        hostname: str,
        port: int,
    ) -> Dict[str, Any]:
        """
        Diagnostic-only TLS handshake.

        This does not establish certificate validity. It only checks whether
        a TLS endpoint responds and records negotiated connection metadata.
        """

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection(
                (hostname, port),
                timeout=7.0,
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname,
                ) as tls_socket:

                    certificate_der = tls_socket.getpeercert(
                        binary_form=True
                    )

                    fingerprint = None

                    if certificate_der:
                        fingerprint = hashlib.sha256(
                            certificate_der
                        ).hexdigest()

                    return {
                        "success": True,
                        "tls_version": tls_socket.version(),
                        "cipher": tls_socket.cipher(),
                        "certificate_presented": bool(certificate_der),
                        "certificate_fingerprint_sha256": fingerprint,
                    }

        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "certificate_presented": False,
            }

    def _sync_fetch_cert(
        self,
        hostname: str,
        port: int = 443,
    ) -> Dict[str, Any]:
        """
        Verify TLS using the system trust store, then certifi when available.

        A failed verification is never converted into a successful
        certificate validation.
        """

        contexts = []

        try:
            contexts.append(
                (
                    "system",
                    ssl.create_default_context(),
                )
            )
        except Exception as exc:
            return {
                "success": False,
                "verification_status": "INDETERMINATE",
                "error": f"Unable to initialize system CA trust: {exc}",
            }

        # certifi provides an additional CA bundle on installations where
        # it is available, such as environments using requests.
        try:
            import certifi

            certifi_context = ssl.create_default_context(
                cafile=certifi.where()
            )

            contexts.append(("certifi", certifi_context))

        except ImportError:
            pass
        except Exception:
            # An unavailable or broken optional CA bundle must not disable
            # the primary system trust verification.
            pass

        verification_errors = []

        for trust_source, context in contexts:
            try:
                result = self._open_verified_connection(
                    hostname,
                    port,
                    context,
                )

                result["verification_status"] = "VERIFIED"
                result["trust_source"] = trust_source

                return result

            except ssl.SSLCertVerificationError as exc:
                verification_errors.append({
                    "source": trust_source,
                    "verify_code": getattr(exc, "verify_code", None),
                    "verify_message": getattr(
                        exc,
                        "verify_message",
                        str(exc),
                    ),
                })

            except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                return {
                    "success": False,
                    "verification_status": "INDETERMINATE",
                    "error": f"TLS connection failed: {exc}",
                    "tls_version": "Unknown",
                }

        # Neither available trust store could verify the certificate.
        # Probe only for diagnostic metadata; never treat this as validation.
        diagnostic = self._probe_unverified_connection(
            hostname,
            port,
        )

        primary_error = (
            verification_errors[0]
            if verification_errors
            else {}
        )

        verify_code = primary_error.get("verify_code")
        verify_message = primary_error.get(
            "verify_message",
            "Certificate verification failed.",
        )

        # These verification failures indicate a concrete certificate
        # problem rather than merely an unavailable issuer in the local CA
        # store.
        confirmed_failure_codes = {
            9,   # Certificate is not yet valid
            10,  # Certificate has expired
            62,  # Hostname mismatch
        }

        if verify_code in confirmed_failure_codes:
            verification_status = "FAILED"
        else:
            verification_status = "INDETERMINATE"

        return {
            "success": False,
            "verification_status": verification_status,
            "verify_code": verify_code,
            "error": verify_message,
            "tls_version": diagnostic.get(
                "tls_version",
                "Unknown",
            ),
            "cipher": diagnostic.get("cipher"),
            "certificate_presented": diagnostic.get(
                "certificate_presented",
                False,
            ),
            "certificate_fingerprint_sha256": diagnostic.get(
                "certificate_fingerprint_sha256"
            ),
            "verification_attempts": verification_errors,
        }

    @staticmethod
    def _parse_certificate_dates(
        cert: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Parse certificate validity dates without inventing fallbacks."""

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        if not_before is None or not_after is None:
            return None, None, None

        try:
            before_timestamp = ssl.cert_time_to_seconds(not_before)
            after_timestamp = ssl.cert_time_to_seconds(not_after)

            before = datetime.datetime.fromtimestamp(
                before_timestamp,
                tz=datetime.timezone.utc,
            )

            after = datetime.datetime.fromtimestamp(
                after_timestamp,
                tz=datetime.timezone.utc,
            )

            now = datetime.datetime.now(datetime.timezone.utc)

            days_remaining = (after - now).days

            return (
                before.isoformat(),
                after.isoformat(),
                days_remaining,
            )

        except (ValueError, TypeError, OverflowError, OSError):
            return None, None, None

    @staticmethod
    def _get_certificate_identity(
        cert: Dict[str, Any],
        hostname: str,
    ) -> Tuple[str, str]:

        issuer_dict = dict(
            item[0] for item in cert.get("issuer", [])
        )

        subject_dict = dict(
            item[0] for item in cert.get("subject", [])
        )

        issuer = (
            issuer_dict.get("organizationName")
            or issuer_dict.get("commonName")
            or "Unknown Issuer"
        )

        subject = (
            subject_dict.get("commonName")
            or hostname
        )

        return issuer, subject

    @staticmethod
    def _detect_mixed_content(
        context: AnalysisContext,
    ) -> Tuple[bool, List[str]]:
        """Inspect static HTML for HTTP resource references."""

        if not context.normalized_url.lower().startswith("https://"):
            return False, []

        if not context.response_body:
            return False, []

        parser = _MixedContentParser(context.normalized_url)

        try:
            parser.feed(context.response_body)
            parser.close()
        except Exception:
            return False, []

        resources = sorted(parser.mixed_resources)

        return bool(resources), resources

    @staticmethod
    def _get_hsts_status(
        response_headers: Dict[str, str],
    ) -> Optional[bool]:
        for name, value in response_headers.items():
            if name.lower() == "strict-transport-security":
                return bool(value and value.strip())

        return False

    async def analyze(
        self,
        context: AnalysisContext,
    ) -> Dict[str, Any]:

        hostname = context.domain
        findings: List[Dict[str, Any]] = []

        try:
            result = await asyncio.to_thread(
                self._sync_fetch_cert,
                hostname,
                443,
            )

        except Exception as exc:
            result = {
                "success": False,
                "verification_status": "INDETERMINATE",
                "error": f"TLS analysis failed: {exc}",
                "tls_version": "Unknown",
            }

        has_mixed_content, mixed_resources = self._detect_mixed_content(
            context
        )

        hsts_status = self._get_hsts_status(
            context.response_headers
        )

        if not result.get("success"):
            verification_status = result.get(
                "verification_status",
                "INDETERMINATE",
            )

            confirmed_failure = verification_status == "FAILED"

            if confirmed_failure:
                findings.append({
                    "id": "tls-invalid",
                    "category": "SECURITY",
                    "title": "TLS Certificate Validation Failed",
                    "status": "FAIL",
                    "impact": "CRITICAL",
                    "description": (
                        "Certificate verification failed: "
                        f"{result.get('error', 'Unknown certificate error')}"
                    ),
                    "remediation": (
                        "Correct the certificate validity or hostname "
                        "configuration and ensure the server presents "
                        "the required certificate chain."
                    ),
                })

            else:
                findings.append({
                    "id": "tls-verification-inconclusive",
                    "category": "SECURITY",
                    "title": "TLS Certificate Verification Inconclusive",
                    "status": "WARN",
                    "impact": "MEDIUM",
                    "description": (
                        "The scanner could not establish certificate "
                        "trust conclusively. This may be caused by a "
                        "local CA trust-store problem or an incomplete "
                        "server certificate chain. "
                        f"Diagnostic: {result.get('error', 'Unknown error')}"
                    ),
                    "remediation": (
                        "Verify the scanner's CA certificates and inspect "
                        "the server's certificate chain before treating "
                        "this result as a confirmed certificate failure."
                    ),
                })

            tls_info = {
                "valid": False if confirmed_failure else None,
                "verificationStatus": verification_status,
                "verificationError": result.get("error"),
                "verificationCode": result.get("verify_code"),
                "trustSource": None,
                "certificatePresented": result.get(
                    "certificate_presented",
                    False,
                ),
                "certificateFingerprintSHA256": result.get(
                    "certificate_fingerprint_sha256"
                ),
                "issuer": "Unknown",
                "subject": hostname,
                "validFrom": None,
                "validTo": None,
                "daysRemaining": None,
                "protocolVersion": result.get(
                    "tls_version",
                    "Unknown",
                ),
                "cipherSuite": (
                    result.get("cipher")[0]
                    if result.get("cipher")
                    else None
                ),
                "hasMixedContent": has_mixed_content,
                "mixedContentResources": mixed_resources,
                "enforcesHttps": context.normalized_url.startswith(
                    "https://"
                ),
                "hstsPreloaded": None,
                "hstsHeaderPresent": hsts_status,
            }

            return {
                "tls_info": tls_info,
                "findings": findings,
            }

        cert = result["cert"]
        tls_version = result["tls_version"]
        cipher = result["cipher"]

        issuer, subject = self._get_certificate_identity(
            cert,
            hostname,
        )

        valid_from, valid_to, days_remaining = (
            self._parse_certificate_dates(cert)
        )

        if tls_version in ("TLSv1.2", "TLSv1.3"):
            findings.append({
                "id": "tls-modern-protocol",
                "category": "SECURITY",
                "title": f"Modern Protocol ({tls_version})",
                "status": "PASS",
                "impact": "INFO",
                "description": (
                    f"The website supports modern TLS encryption "
                    f"protocol {tls_version}."
                ),
            })

        else:
            findings.append({
                "id": "tls-legacy-protocol",
                "category": "SECURITY",
                "title": f"Legacy Protocol ({tls_version})",
                "status": "WARN",
                "impact": "HIGH",
                "description": (
                    f"The website uses an older TLS protocol "
                    f"({tls_version})."
                ),
                "remediation": (
                    "Configure the server to support TLS 1.2 and TLS 1.3."
                ),
            })

        if days_remaining is None:
            findings.append({
                "id": "tls-date-unavailable",
                "category": "SECURITY",
                "title": "Certificate Validity Dates Unavailable",
                "status": "WARN",
                "impact": "LOW",
                "description": (
                    "The certificate was verified, but its validity "
                    "dates could not be parsed."
                ),
                "remediation": (
                    "Inspect the certificate metadata and verify its "
                    "validity period."
                ),
            })

        elif days_remaining < 0:
            findings.append({
                "id": "tls-expired",
                "category": "SECURITY",
                "title": "TLS Certificate Expired",
                "status": "FAIL",
                "impact": "CRITICAL",
                "description": (
                    f"The TLS certificate expired "
                    f"{abs(days_remaining)} days ago."
                ),
                "remediation": "Renew the TLS certificate immediately.",
            })

        elif days_remaining < 15:
            findings.append({
                "id": "tls-expiring-soon",
                "category": "SECURITY",
                "title": "TLS Certificate Expiring Soon",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    f"The TLS certificate will expire in "
                    f"{days_remaining} days."
                ),
                "remediation": (
                    "Renew the TLS certificate before it expires."
                ),
            })

        else:
            findings.append({
                "id": "tls-cert-valid",
                "category": "SECURITY",
                "title": "Valid Certificate Authority Certificate",
                "status": "PASS",
                "impact": "INFO",
                "description": (
                    f"Issued by {issuer}, valid for another "
                    f"{days_remaining} days."
                ),
            })

        if has_mixed_content:
            findings.append({
                "id": "tls-mixed-content",
                "category": "SECURITY",
                "title": "Mixed Content References Detected",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": (
                    f"{len(mixed_resources)} HTTP resource reference(s) "
                    "were found in the inspected static HTML."
                ),
                "remediation": (
                    "Serve referenced resources over HTTPS."
                ),
                "details": mixed_resources,
            })

        tls_info = {
            "valid": True,
            "verificationStatus": "VERIFIED",
            "verificationError": None,
            "verificationCode": None,
            "trustSource": result.get("trust_source"),
            "certificatePresented": True,
            "certificateFingerprintSHA256": None,
            "issuer": issuer,
            "subject": subject,
            "validFrom": valid_from,
            "validTo": valid_to,
            "daysRemaining": (
                max(0, days_remaining)
                if days_remaining is not None
                else None
            ),
            "protocolVersion": tls_version,
            "cipherSuite": cipher[0] if cipher else None,
            "hasMixedContent": has_mixed_content,
            "mixedContentResources": mixed_resources,
            "enforcesHttps": context.normalized_url.startswith(
                "https://"
            ),
            # HSTS preload status requires an independent preload-list
            # lookup; the response header alone cannot establish it.
            "hstsPreloaded": None,
            "hstsHeaderPresent": hsts_status,
        }

        return {
            "tls_info": tls_info,
            "findings": findings,
        }
