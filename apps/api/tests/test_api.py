import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "RevShield" in data["service"]

@pytest.mark.asyncio
async def test_analyze_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "analysisId" in data
    assert data["domain"] == "example.com"
    assert "stage" in data

@pytest.mark.asyncio
async def test_extension_config_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/api/v1/extension/config")
    assert response.status_code == 200
    data = response.json()
    assert data["ruleSignaturesCount"] > 0
