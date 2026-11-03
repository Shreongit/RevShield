
import ipaddress
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple, Union
from urllib.parse import urlparse

import bcrypt
from jose import jwt

from app.core.config import settings


BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

ALLOWED_PORTS = {80, 443, 8080, 8443}

NUMERIC_IPV4_PATTERN = re.compile(r"^\d+(?:\.\d+){3}$")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8")[:72],
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()

    return bcrypt.hashpw(
        password.encode("utf-8")[:72],
        salt,
    ).decode("utf-8")


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
    }

    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def is_ip_blocked(ip_str: str) -> bool:
    """Return True when an IP is private, reserved, or restricted."""

    try:
        ip_obj = ipaddress.ip_address(ip_str)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return True

        return any(
            ip_obj in network
            for network in BLOCKED_IP_NETWORKS
        )

    except (ValueError, TypeError):
        return True


def _normalize_hostname(
    hostname: str,
) -> Tuple[bool, str, str]:
    """Validate hostname syntax and convert IDNs to ASCII."""

    if not hostname:
        return False, "", "Hostname is required."

    if "%" in hostname:
        return False, "", "Scoped IP addresses are not permitted."

    hostname = hostname.rstrip(".")

    if not hostname:
        return False, "", "Invalid hostname."

    if NUMERIC_IPV4_PATTERN.fullmatch(hostname):
        try:
            ipaddress.IPv4Address(hostname)
        except ValueError:
            return False, "", f"Invalid IPv4 address '{hostname}'."

    try:
        ascii_hostname = (
            hostname.encode("idna").decode("ascii").lower()
        )
    except UnicodeError:
        return (
            False,
            "",
            "Hostname contains invalid internationalized characters.",
        )

    if len(ascii_hostname) > 253:
        return False, "", "Hostname exceeds the maximum permitted length."

    labels = ascii_hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9-]+", label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            return False, "", f"Invalid hostname label in '{hostname}'."

    return True, ascii_hostname, ""


def validate_target_url_security_with_addresses(
    raw_url: str,
) -> Tuple[bool, str, List[str], str]:
    """
    Validate a URL and return the exact IP addresses approved for connection.

    Returns:
        (is_valid, normalized_url, validated_addresses, error_message)

    IMPORTANT:
        The returned addresses must be used by the actual network transport.
        Performing another DNS lookup when connecting would reintroduce
        the DNS rebinding vulnerability.
    """

    if not isinstance(raw_url, str) or not raw_url.strip():
        return False, "", [], "URL is required and must be a non-empty string."

    url = raw_url.strip()

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        return False, "", [], "URL contains invalid control characters."

    if "://" in url:
        supplied_scheme = url.split("://", 1)[0].lower()

        if supplied_scheme not in ("http", "https"):
            return (
                False,
                "",
                [],
                f"Scheme '{supplied_scheme}' is not allowed. "
                "Only HTTP and HTTPS are permitted.",
            )
    else:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return False, "", [], f"Malformed URL: {exc}"

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        return (
            False,
            "",
            [],
            f"Scheme '{scheme}' is not allowed. "
            "Only HTTP and HTTPS are permitted.",
        )

    if parsed.username is not None or parsed.password is not None:
        return (
            False,
            "",
            [],
            "URLs containing username or password credentials are not permitted.",
        )

    try:
        port = parsed.port
    except ValueError:
        return False, "", [], "URL contains an invalid port number."

    if port is not None and port not in ALLOWED_PORTS:
        return (
            False,
            "",
            [],
            f"Port {port} is not supported for public security scanning.",
        )

    hostname = parsed.hostname

    if not hostname:
        return (
            False,
            "",
            [],
            "URL must contain a valid domain name or public IP address.",
        )

    hostname_lower = hostname.lower()

    if (
        hostname_lower in BLOCKED_HOSTNAMES
        or hostname_lower.endswith(".internal")
        or hostname_lower.endswith(".local")
    ):
        return (
            False,
            "",
            [],
            f"Access to host '{hostname}' is restricted for security reasons.",
        )

    resolved_addresses = set()

    # Direct IP addresses do not require DNS resolution.
    try:
        ip_obj = ipaddress.ip_address(hostname)

        if is_ip_blocked(str(ip_obj)):
            return (
                False,
                "",
                [],
                f"IP address '{hostname}' is in a restricted or private range.",
            )

        resolved_addresses.add(str(ip_obj))

    except ValueError:
        valid_hostname, normalized_hostname, error = (
            _normalize_hostname(hostname)
        )

        if not valid_hostname:
            return False, "", [], error

        if (
            normalized_hostname in BLOCKED_HOSTNAMES
            or normalized_hostname.endswith(".internal")
            or normalized_hostname.endswith(".local")
        ):
            return (
                False,
                "",
                [],
                f"Access to host '{hostname}' is restricted for security reasons.",
            )

        # Resolve all addresses. Reject the entire hostname if even one
        # result points to a restricted destination.
        try:
            addr_info = socket.getaddrinfo(
                normalized_hostname,
                port or (443 if scheme == "https" else 80),
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )

            if not addr_info:
                return (
                    False,
                    "",
                    [],
                    f"Could not resolve host '{hostname}'.",
                )

            for item in addr_info:
                resolved_ip = item[4][0]

                if is_ip_blocked(resolved_ip):
                    return (
                        False,
                        "",
                        [],
                        f"Host '{hostname}' resolves to a restricted/private "
                        f"IP ({resolved_ip}).",
                    )

                resolved_addresses.add(
                    str(ipaddress.ip_address(resolved_ip))
                )

        except socket.gaierror:
            return (
                False,
                "",
                [],
                f"Domain '{hostname}' could not be resolved (DNS lookup failed).",
            )

        except (OSError, ValueError) as exc:
            return (
                False,
                "",
                [],
                f"Security verification failed during DNS lookup: {exc}",
            )

    if not resolved_addresses:
        return False, "", [], f"Could not resolve host '{hostname}'."

    # Normalize the hostname in the URL as well.
    try:
        normalized_hostname = (
            str(ipaddress.ip_address(hostname))
            if not hostname.lower().startswith("0x")
            else hostname
        )
    except ValueError:
        normalized_hostname = normalized_hostname

    if ":" in normalized_hostname:
        normalized_netloc = f"[{normalized_hostname}]"
    else:
        normalized_netloc = normalized_hostname

    if port is not None:
        normalized_netloc += f":{port}"

    normalized_url = parsed._replace(
        scheme=scheme,
        netloc=normalized_netloc,
    ).geturl()

    return (
        True,
        normalized_url,
        sorted(resolved_addresses),
        "",
    )


def validate_target_url_security(
    raw_url: str,
) -> Tuple[bool, str, str]:
    """
    Backward-compatible URL validation interface.

    Existing callers retain the original three-value return format.
    """

    valid, normalized_url, _, error = (
        validate_target_url_security_with_addresses(raw_url)
    )

    return valid, normalized_url, error
