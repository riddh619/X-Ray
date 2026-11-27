#!/usr/bin/env python3
"""
X-Ray Simulation Server & Canary Probe Coordinator
FastAPI backend for controlled mock banking environment and Playwright Canary Probe.
"""

import asyncio
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------

app = FastAPI(
    title="X-Ray Security Simulation Server",
    description="Controlled mock banking and Playwright Canary Probe environment",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent / "webpages"
MOCK_BANK_DIR = BASE_DIR / "mock-bank"
ATTACK_DIR = BASE_DIR / "attacks"

# ---------------------------------------------------------------------------
# Brand Registry
# ---------------------------------------------------------------------------

BRAND_REGISTRY = {
    "demo-bank-a": {
        "brandId": "demo-bank-a",
        "brandName": "DemoBank Alpha",
        "officialDomain": "demo-bank-a.example",
        "aliases": ["demobankalpha.example"],
        "keywords": ["DemoBank Alpha", "Alpha Banking", "DemoBank"],
    },
    "demo-bank-b": {
        "brandId": "demo-bank-b",
        "brandName": "DemoBank Beta",
        "officialDomain": "demo-bank-b.example",
        "aliases": ["demobankbeta.example", "beta-bank.example"],
        "keywords": ["DemoBank Beta", "Beta Banking", "DemoBank B"],
    },
    "demo-bank-c": {
        "brandId": "demo-bank-c",
        "brandName": "DemoBank Gamma",
        "officialDomain": "demo-bank-c.example",
        "aliases": ["gammabank.example"],
        "keywords": ["DemoBank Gamma", "Gamma Banking", "DemoBank G"],
    },
}

# ---------------------------------------------------------------------------
# Canary Probe Execution Engine (Playwright)
# ---------------------------------------------------------------------------

last_canary_result: Dict[str, Any] = {
    "status": "idle",
    "tokenStatus": "none",
    "transmissionAttempted": False,
    "externalTransmissionBlocked": True,
    "verdict": "No active probe executed yet.",
    "startedAt": 0,
    "finishedAt": 0,
}


class CanaryProbeRequest(BaseModel):
    targetUrl: Optional[str] = "http://127.0.0.1:8000/mock-bank/fake.html"
    customToken: Optional[str] = None


async def run_playwright_canary_probe(target_url: str, synthetic_token: str) -> Dict[str, Any]:
    """
    Executes a synthetic OTP exfiltration probe inside an isolated Playwright browser context.
    Strictly intercepts and blocks outbound traffic, observing if the target webpage attempts
    to transmit the synthetic token.
    """
    started_at = int(time.time() * 1000)
    transmission_attempted = False
    observed_api = None
    attempted_destination = None

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            # Launch isolated chromium instance
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )

            # Strict request interception
            async def handle_route(route, request):
                nonlocal transmission_attempted, observed_api, attempted_destination
                url = request.url
                post_data = request.post_data or ""

                # Check if synthetic token is present in the request (body or url)
                if (
                    synthetic_token in post_data
                    or (request.post_data_buffer and synthetic_token.encode() in request.post_data_buffer)
                    or synthetic_token in url
                ):
                    transmission_attempted = True
                    attempted_destination = url
                    res_type = request.resource_type
                    if res_type in ["fetch", "xhr", "beacon"]:
                        observed_api = res_type
                    else:
                        observed_api = "fetch" if "fetch" in url else "form"

                    # Abort outbound exfiltration request immediately
                    await route.abort("blockedbyclient")
                    return

                # Allow only safe local simulation resources
                if "127.0.0.1" in url or "localhost" in url or url.startswith("file://") or url.startswith("data:"):
                    await route.continue_()
                else:
                    # Block all external network access during probe
                    await route.abort("blockedbyclient")

            await context.route("**/*", handle_route)

            page = await context.new_page()
            await page.goto(target_url, wait_until="domcontentloaded", timeout=8000)

            # Locate OTP field and populate synthetic token
            otp_selectors = [
                'input[name="otp"]',
                '#otp',
                'input[autocomplete="one-time-code"]',
                'input[placeholder*="OTP"]',
                'input[type="text"]',
            ]

            otp_field = None
            for sel in otp_selectors:
                el = await page.query_selector(sel)
                if el:
                    otp_field = el
                    break

            if otp_field:
                # Remove maxlength restrictions if present to allow full synthetic token
                try:
                    await page.evaluate("""() => {
                        const inputs = document.querySelectorAll('input');
                        inputs.forEach(i => {
                            i.removeAttribute('maxlength');
                            i.maxLength = 256;
                        });
                    }""")
                except Exception:
                    pass

                await otp_field.fill(synthetic_token)
                await asyncio.sleep(0.3)

                # Submit form if present
                submit_button = await page.query_selector('button[type="submit"], input[type="submit"], #submit-phish-btn')
                if submit_button:
                    await submit_button.click()
                else:
                    await page.keyboard.press("Enter")

                # Allow brief window for asynchronous network transmission attempt
                await asyncio.sleep(1.5)

            await context.close()
            await browser.close()

    except Exception as e:
        finished_at = int(time.time() * 1000)
        return {
            "status": "error",
            "tokenStatus": "generated",
            "token": synthetic_token,
            "error": str(e),
            "transmissionAttempted": False,
            "externalTransmissionBlocked": True,
            "verdict": f"Canary probe encountered error: {str(e)}",
            "startedAt": started_at,
            "finishedAt": finished_at,
        }

    finished_at = int(time.time() * 1000)

    if transmission_attempted:
        verdict = "POTENTIAL EXFILTRATION ATTEMPT CONFIRMED"
        status = "transmission_detected"
    else:
        verdict = "NO EXFILTRATION DETECTED - Webpage did not attempt to transmit synthetic OTP."
        status = "no_transmission"

    return {
        "status": status,
        "tokenStatus": "generated",
        "token": synthetic_token,
        "observedApi": observed_api or "fetch",
        "attemptedDestination": attempted_destination or "None",
        "transmissionAttempted": transmission_attempted,
        "externalTransmissionBlocked": True,
        "verdict": verdict,
        "startedAt": started_at,
        "finishedAt": finished_at,
    }


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return FileResponse(str(MOCK_BANK_DIR / "official.html"))


@app.get("/mock-bank/official.html")
async def official_bank_page():
    return FileResponse(str(MOCK_BANK_DIR / "official.html"))


@app.get("/mock-bank/otp.html")
async def official_bank_otp():
    return FileResponse(str(MOCK_BANK_DIR / "otp.html"))


@app.get("/mock-bank/styles.css")
async def mock_bank_styles():
    return FileResponse(str(MOCK_BANK_DIR / "styles.css"))


@app.get("/mock-bank/fake.html")
@app.get("/attacks/fake-bank.html")
async def fake_bank_page():
    return FileResponse(str(ATTACK_DIR / "fake-bank.html"))


@app.get("/attacks/tracker.html")
async def tracker_page():
    return FileResponse(str(ATTACK_DIR / "tracker.html"))


# ---------------------------------------------------------------------------
# Canary Probe Routes
# ---------------------------------------------------------------------------

@app.post("/canary/probe/start")
async def start_canary_probe(body: CanaryProbeRequest):
    global last_canary_result

    target_url = body.targetUrl or "http://127.0.0.1:8000/mock-bank/fake.html"
    synthetic_token = body.customToken or f"XRAY_TEST_OTP_{random.randint(10000, 99999)}"

    result = await run_playwright_canary_probe(target_url, synthetic_token)
    last_canary_result = result
    return result


@app.get("/canary/probe/status")
async def get_canary_probe_status():
    return last_canary_result


# ---------------------------------------------------------------------------
# Simulated Attacker Endpoints
# ---------------------------------------------------------------------------

@app.post("/attacks/fetch-collect")
async def attacks_fetch_collect(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "status": "intercepted_by_endpoint",
        "endpoint": "fetch-collect",
        "received": body,
        "timestamp": int(time.time() * 1000),
    }


@app.post("/attacks/xhr-exfil")
async def attacks_xhr_exfil(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "status": "intercepted_by_endpoint",
        "endpoint": "xhr-exfil",
        "received": body,
        "timestamp": int(time.time() * 1000),
    }


@app.post("/attacks/sendbeacon-exfil")
async def attacks_beacon_exfil(request: Request):
    body_raw = await request.body()
    return {
        "status": "intercepted_by_endpoint",
        "endpoint": "sendbeacon-exfil",
        "bytesReceived": len(body_raw),
        "timestamp": int(time.time() * 1000),
    }


@app.post("/attacks/external-form")
async def attacks_external_form(request: Request):
    return HTMLResponse("<html><body><h3>Form data received at attacker endpoint.</h3></body></html>")


@app.get("/brand/{brand_id}")
async def get_brand(brand_id: str):
    if brand_id in BRAND_REGISTRY:
        return BRAND_REGISTRY[brand_id]
    raise HTTPException(status_code=404, detail="Brand not registered")


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "x-ray-simulation-server",
        "timestamp": int(time.time()),
    }


# Mount static files as fallbacks
app.mount("/mock-bank", StaticFiles(directory=str(MOCK_BANK_DIR)), name="mock-bank")
app.mount("/attacks", StaticFiles(directory=str(ATTACK_DIR)), name="attacks")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
