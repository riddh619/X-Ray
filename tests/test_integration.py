"""
X-Ray Integration Tests
Tests simulation server routes, Canary Probe Playwright execution,
and attack endpoint interception.
"""

import asyncio
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport

import sys
sys.path.append(str(Path(__file__).parent.parent / "simulation"))

from server import app, run_playwright_canary_probe

SIMULATION_DIR = Path(__file__).parent.parent / "simulation" / "webpages"


@pytest.mark.asyncio
class TestSimulationServerRoutes:
    async def test_health_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/health")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "healthy"
            assert "x-ray-simulation-server" in data["service"]

    async def test_official_bank_page_served(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/mock-bank/official.html")
            assert res.status_code == 200
            assert "DemoBank Alpha" in res.text

    async def test_official_bank_otp_served(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/mock-bank/otp.html")
            assert res.status_code == 200
            assert "Two-Factor Authentication" in res.text

    async def test_fake_bank_page_served(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/mock-bank/fake.html")
            assert res.status_code == 200
            assert "Simulated Malicious Webpage" in res.text

    async def test_brand_registry_api(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/brand/demo-bank-a")
            assert res.status_code == 200
            data = res.json()
            assert data["officialDomain"] == "demo-bank-a.example"

    async def test_attacker_endpoints(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # fetch attack endpoint
            res = await client.post("/attacks/fetch-collect", json={"otp": "123456"})
            assert res.status_code == 200
            assert res.json()["status"] == "intercepted_by_endpoint"

            # xhr attack endpoint
            res_xhr = await client.post("/attacks/xhr-exfil", json={"otp": "654321"})
            assert res_xhr.status_code == 200
            assert res_xhr.json()["status"] == "intercepted_by_endpoint"


@pytest.mark.asyncio
class TestCanaryProbePlaywrightIntegration:
    async def test_canary_probe_detects_fake_bank_exfiltration(self):
        fake_bank_url = f"file:///{SIMULATION_DIR / 'attacks' / 'fake-bank.html'}"
        token = "XRAY_TEST_OTP_77182"
        result = await run_playwright_canary_probe(fake_bank_url, token)

        assert result["status"] == "transmission_detected"
        assert result["transmissionAttempted"] is True
        assert result["externalTransmissionBlocked"] is True
        assert result["token"] == token
        assert "POTENTIAL EXFILTRATION ATTEMPT CONFIRMED" in result["verdict"]

    async def test_canary_probe_handles_safe_bank_no_exfiltration(self):
        official_otp_url = f"file:///{SIMULATION_DIR / 'mock-bank' / 'otp.html'}"
        token = "XRAY_TEST_OTP_11223"
        result = await run_playwright_canary_probe(official_otp_url, token)

        assert result["status"] == "no_transmission"
        assert result["transmissionAttempted"] is False
        assert "NO EXFILTRATION DETECTED" in result["verdict"]
