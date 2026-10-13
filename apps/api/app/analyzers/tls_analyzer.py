import asyncio
import datetime
import socket
import ssl
from typing import Any, Dict, List
from app.analyzers.base import BaseAnalyzer, AnalysisContext

class TLSAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "tls_analyzer"

    def _sync_fetch_cert(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        "success": True,
                        "cert": cert,
                        "tls_version": tls_version,
                        "cipher": cipher
                    }
        except ssl.SSLCertVerificationError as e:
            return {
                "success": False,
                "error": f"Certificate verification failed: {e.verify_message}",
                "tls_version": "Unknown"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"TLS connection failed: {str(e)}",
                "tls_version": "None"
            }

    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        hostname = context.domain
        findings: List[Dict[str, Any]] = []

        # Run socket connection in thread pool
        res = await asyncio.to_thread(self._sync_fetch_cert, hostname, 443)

        if not res["success"]:
            findings.append({
                "id": "tls-invalid",
                "category": "SECURITY",
                "title": "TLS/SSL Certificate Invalid or Missing",
                "status": "FAIL",
                "impact": "CRITICAL",
                "description": f"Unable to establish a trusted TLS connection: {res.get('error', 'Unknown SSL error')}",
                "remediation": "Install a valid SSL/TLS certificate issued by a trusted Certificate Authority (e.g., Let's Encrypt)."
            })
            return {
                "tls_info": {
                    "valid": False,
                    "issuer": "None",
                    "subject": hostname,
                    "validFrom": "",
                    "validTo": "",
                    "daysRemaining": 0,
                    "protocolVersion": res.get("tls_version", "None"),
                    "cipherSuite": None,
                    "hasMixedContent": False,
                    "enforcesHttps": context.normalized_url.startswith("https://"),
                    "hstsPreloaded": False
                },
                "findings": findings
            }

        cert = res["cert"]
        tls_version = res["tls_version"]
        cipher = res["cipher"]

        # Parse issuer and subject
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))

        issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"
        subject_cn = subject_dict.get("commonName") or hostname

        # Parse dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        days_remaining = 0
        valid_to_iso = ""
        valid_from_iso = ""

        try:
            # SSL date format: 'Apr 15 12:00:00 2026 GMT'
            dt_after = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            dt_before = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            days_remaining = (dt_after - now).days
            valid_to_iso = dt_after.isoformat()
            valid_from_iso = dt_before.isoformat()
        except Exception:
            days_remaining = 30

        # Evaluate TLS protocol version
        if tls_version in ("TLSv1.3", "TLSv1.2"):
            findings.append({
                "id": "tls-modern-protocol",
                "category": "SECURITY",
                "title": f"Modern Protocol ({tls_version})",
                "status": "PASS",
                "impact": "INFO",
                "description": f"The website supports modern, secure TLS encryption protocol {tls_version}.",
            })
        else:
            findings.append({
                "id": "tls-legacy-protocol",
                "category": "SECURITY",
                "title": f"Legacy Protocol ({tls_version})",
                "status": "WARN",
                "impact": "HIGH",
                "description": f"The website uses an older or deprecated TLS protocol ({tls_version}), which contains known vulnerabilities.",
                "remediation": "Upgrade server configuration to support TLS 1.2 and TLS 1.3 only."
            })

        # Evaluate certificate expiration
        if days_remaining < 0:
            findings.append({
                "id": "tls-expired",
                "category": "SECURITY",
                "title": "TLS Certificate Expired",
                "status": "FAIL",
                "impact": "CRITICAL",
                "description": f"The TLS certificate expired {abs(days_remaining)} days ago.",
                "remediation": "Renew the TLS certificate immediately."
            })
        elif days_remaining < 15:
            findings.append({
                "id": "tls-expiring-soon",
                "category": "SECURITY",
                "title": "TLS Certificate Expiring Soon",
                "status": "WARN",
                "impact": "MEDIUM",
                "description": f"The TLS certificate will expire in {days_remaining} days.",
                "remediation": "Renew the TLS certificate before it expires to prevent service disruption."
            })
        else:
            findings.append({
                "id": "tls-cert-valid",
                "category": "SECURITY",
                "title": "Valid Certificate Authority Certificate",
                "status": "PASS",
                "impact": "INFO",
                "description": f"Issued by {issuer_org}, valid for another {days_remaining} days.",
            })

        cipher_name = cipher[0] if cipher and isinstance(cipher, tuple) else None

        tls_info = {
            "valid": True,
            "issuer": issuer_org,
            "subject": subject_cn,
            "validFrom": valid_from_iso,
            "validTo": valid_to_iso,
            "daysRemaining": max(0, days_remaining),
            "protocolVersion": tls_version,
            "cipherSuite": cipher_name,
            "hasMixedContent": False,
            "enforcesHttps": context.normalized_url.startswith("https://"),
            "hstsPreloaded": "strict-transport-security" in context.response_headers and "preload" in context.response_headers.get("strict-transport-security", "").lower()
        }

        return {
            "tls_info": tls_info,
            "findings": findings
        }
