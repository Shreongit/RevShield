import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple, Union
from urllib.parse import urlparse
import bcrypt
from jose import jwt
from app.core.config import settings

# Private and non-routable CIDR ranges
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / AWS / GCP / Azure metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
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

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8")[:72], salt).decode("utf-8")

def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"exp": expire, "sub": str(subject)}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address string belongs to any blocked/private CIDR block."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return True
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True

def validate_target_url_security(raw_url: str) -> Tuple[bool, str, str]:
    """
    Validate target URL against SSRF, dangerous protocols, and private/internal destinations.
    Returns: (is_valid: bool, normalized_url: str, error_message: str)
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "", "URL is required and must be a non-empty string."

    url = raw_url.strip()
    if "://" in url:
        scheme = url.split("://")[0].lower()
        if scheme not in ("http", "https"):
            return False, "", f"Scheme '{scheme}' is not allowed. Only HTTP and HTTPS are permitted."
    else:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, "", f"Malformed URL: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "", f"Scheme '{parsed.scheme}' is not allowed. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "", "URL must contain a valid domain name or public IP address."

    hostname_lower = hostname.lower()

    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
        return False, "", f"Access to host '{hostname}' is restricted for security reasons."

    # Check if direct IP was passed
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_blocked(str(ip_obj)):
            return False, "", f"IP address '{hostname}' is in a restricted or private range."
    except ValueError:
        # It is a domain name, resolve DNS to verify all destination IPs
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            if not addr_info:
                return False, "", f"Could not resolve host '{hostname}'."
            for item in addr_info:
                sockaddr = item[4]
                resolved_ip = sockaddr[0]
                if is_ip_blocked(resolved_ip):
                    return False, "", f"Host '{hostname}' resolves to a restricted/private IP ({resolved_ip})."
        except socket.gaierror:
            return False, "", f"Domain '{hostname}' could not be resolved (DNS lookup failed)."
        except Exception as e:
            return False, "", f"Security verification failed during DNS lookup: {str(e)}"

    port = parsed.port
    if port and port not in (80, 443, 8080, 8443):
        return False, "", f"Port {port} is not supported for public security scanning."

    normalized_url = parsed.geturl()
    return True, normalized_url, ""
