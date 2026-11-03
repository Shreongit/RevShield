import asyncio
import ssl

import httpcore

from app.core.pinned_transport import (
    PinnedAddressRegistry,
    PinnedAsyncNetworkBackend,
)


class FakeTLSStream:
    def __init__(self):
        self.tls_kwargs = None

    async def start_tls(self, **kwargs):
        self.tls_kwargs = kwargs
        return self


class FakeNetworkBackend:
    def __init__(self):
        self.calls = []
        self.stream = FakeTLSStream()

    async def connect_tcp(self, **kwargs):
        self.calls.append(kwargs)
        return self.stream

    async def sleep(self, seconds):
        pass


def test_tls_preserves_original_hostname_and_verification():
    async def run():
        registry = PinnedAddressRegistry()
        registry.register("example.com", 443, ["8.8.8.8"])

        fake = FakeNetworkBackend()
        backend = PinnedAsyncNetworkBackend(
            registry,
            delegate=fake,
        )

        ssl_context = ssl.create_default_context()

        connection = httpcore.AsyncHTTPConnection(
            origin=httpcore.Origin(
                scheme=b"https",
                host=b"example.com",
                port=443,
            ),
            ssl_context=ssl_context,
            network_backend=backend,
        )

        request = httpcore.Request(
            method="GET",
            url="https://example.com/",
        )

        await connection._connect(request)

        assert fake.calls[0]["host"] == "8.8.8.8"
        assert fake.stream.tls_kwargs["server_hostname"] == "example.com"

        context = fake.stream.tls_kwargs["ssl_context"]
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

        await connection.aclose()

    asyncio.run(run())
