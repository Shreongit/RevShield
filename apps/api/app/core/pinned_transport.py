
"""
DNS-pinned HTTPX transport for SSRF-resistant outbound connections.

Requires:
    httpx >= 0.28, < 1
    httpcore >= 1.0, < 2

The transport uses HTTPcore's network backend to connect directly
to previously validated IP addresses while preserving the original
hostname for HTTP Host headers and TLS certificate verification.
"""

import ipaddress
import threading
from typing import Iterable, Optional
from urllib.parse import urlparse

import httpcore
import httpx

from httpcore._backends.auto import AutoBackend


class PinnedAddressRegistry:
    """Stores approved destination IPs for hostname/port pairs."""

    def __init__(self):
        self._addresses = {}
        self._lock = threading.RLock()

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        if isinstance(hostname, bytes):
            hostname = hostname.decode("ascii")

        return hostname.strip("[]").rstrip(".").lower()

    def register(
        self,
        hostname: str,
        port: int,
        addresses: Iterable[str],
    ) -> None:
        """Register only explicitly validated public IP addresses."""

        normalized_hostname = self._normalize_hostname(hostname)

        if not normalized_hostname:
            raise ValueError("A hostname is required.")

        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("A valid destination port is required.")

        validated = []

        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid pinned IP address: {address}"
                ) from exc

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise ValueError(
                    f"Restricted IP address cannot be pinned: {ip}"
                )

            validated.append(str(ip))

        if not validated:
            raise ValueError(
                "At least one validated destination IP is required."
            )

        with self._lock:
            self._addresses[
                (normalized_hostname, port)
            ] = tuple(dict.fromkeys(validated))

    def register_url(
        self,
        url: str,
        addresses: Iterable[str],
    ) -> None:
        """Register validated addresses for a normalized HTTP URL."""

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("URL does not contain a hostname.")

        port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )

        self.register(hostname, port, addresses)

    def get(
        self,
        hostname: str,
        port: int,
    ) -> tuple[str, ...]:
        """Return pinned IPs or an empty tuple when not registered."""

        key = (
            self._normalize_hostname(hostname),
            port,
        )

        with self._lock:
            return self._addresses.get(key, ())

    def clear(self) -> None:
        """Remove all registered destinations."""

        with self._lock:
            self._addresses.clear()


class PinnedAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    HTTPcore network backend that never resolves destination hostnames.

    HTTPcore supplies the original hostname to connect_tcp().
    This backend replaces it with an explicitly registered IP.

    TLS is still established by HTTPcore using the original origin
    hostname, preserving SNI and certificate hostname verification.
    """

    def __init__(
        self,
        registry: PinnedAddressRegistry,
        delegate=None,
    ):
        self.registry = registry
        self.delegate = delegate or AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options=None,
    ):
        addresses = self.registry.get(host, port)

        if not addresses:
            raise httpcore.ConnectError(
                f"Connection blocked: no validated IP registered "
                f"for {host}:{port}."
            )

        last_error = None

        for address in addresses:
            try:
                # The delegate receives an IP literal, never the hostname.
                return await self.delegate.connect_tcp(
                    host=address,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )

            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc

        raise httpcore.ConnectError(
            f"Could not connect to any validated IP for {host}:{port}."
        ) from last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options=None,
    ):
        raise httpcore.ConnectError(
            "Unix socket connections are not permitted."
        )

    async def sleep(self, seconds: float) -> None:
        await self.delegate.sleep(seconds)


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """
    HTTPX transport using validated, DNS-pinned TCP connections.

    Do not configure a proxy or Unix socket with this transport.
    Environment proxy settings are deliberately ignored.
    """

    def __init__(
        self,
        registry: PinnedAddressRegistry,
        verify=True,
        limits: Optional[httpx.Limits] = None,
        http1: bool = True,
        http2: bool = False,
        local_address: Optional[str] = None,
        retries: int = 0,
        socket_options=None,
    ):
        if not isinstance(registry, PinnedAddressRegistry):
            raise TypeError(
                "registry must be a PinnedAddressRegistry instance."
            )

        if not http1:
            raise ValueError("HTTP/1.1 must remain enabled.")

        super().__init__(
            verify=verify,
            trust_env=False,
            http1=http1,
            http2=http2,
            limits=limits or httpx.Limits(),
            proxy=None,
            uds=None,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
        )

        if not isinstance(self._pool, httpcore.AsyncConnectionPool):
            raise RuntimeError(
                "Unsupported HTTPcore connection pool implementation."
            )

        self.registry = registry

        # Replace the connection pool's network backend.
        # The original TLS configuration and HTTP connection pool remain.
        self._pool._network_backend = PinnedAsyncNetworkBackend(
            registry=registry
        )
