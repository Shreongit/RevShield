import asyncio
import httpcore

from app.core.pinned_transport import (
    PinnedAddressRegistry,
    PinnedAsyncNetworkBackend,
)


class FakeBackend:
    def __init__(self):
        self.calls = []

    async def connect_tcp(self, **kwargs):
        self.calls.append(kwargs)
        return "CONNECTED"

    async def sleep(self, seconds):
        pass


def test_backend_connects_using_pinned_ip():
    async def run():
        registry = PinnedAddressRegistry()
        registry.register("example.com", 443, ["8.8.8.8"])

        fake = FakeBackend()
        backend = PinnedAsyncNetworkBackend(registry, delegate=fake)

        result = await backend.connect_tcp(host="example.com", port=443)

        assert result == "CONNECTED"
        assert len(fake.calls) == 1
        assert fake.calls[0]["host"] == "8.8.8.8"

    asyncio.run(run())


def test_backend_rejects_unregistered_hostname():
    async def run():
        registry = PinnedAddressRegistry()
        fake = FakeBackend()
        backend = PinnedAsyncNetworkBackend(registry, delegate=fake)

        try:
            await backend.connect_tcp(host="example.com", port=443)
            assert False, "Expected connection to be blocked"
        except httpcore.ConnectError:
            pass

        assert fake.calls == []

    asyncio.run(run())
