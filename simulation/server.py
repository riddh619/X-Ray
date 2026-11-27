#!/usr/bin/env python3
"""
X-Ray Simulation Server
FastAPI backend for controlled mock banking environment.
Serves the official and fake banking pages.
Coordinates Canary Probe tests.
Provides simulated attacker endpoints for detection.
"""

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import json
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="X-Ray Simulation Server",
    description="Controlled mock banking environment for browser security testing",
    version="1.0.0"
)

# Enable CORS for local extension development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Directory Setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent / "webpages"
MOCK_BANK_DIR = BASE_DIR / "mock-bank"
ATTACK_DIR = BASE_DIR / "attacks"

# Mount static directories
app.mount("/mock-bank", StaticFiles(directory=str(MOCK_BANK_DIR)), name="mock-bank")
app.mount("/attacks", StaticFiles(directory=str(ATTACK_DIR)), name="attacks")


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

# Brand registry for tests
BRAND_REGISTRY = {
    "demo-bank-a": {
        "officialDomain": "demo-bank-a.example",
        "brandName": "DemoBank Alpha",
        "logoColor": "#06b6d4",
    },
    "demo-bank-b": {
        "officialDomain": "demo-bank-b.example",
        "brandName": "DemoBank Beta",
        "logoColor": "#10b981",
    },
}

# Track canary probe results
canary_state = {
    "active": False,
    "token": None,
    "transmissionAttempted": False,
    "detected": False,
}


@app.get("/")
async def root():
    """Serve the official mock banking page."""
    return FileResponse(str(MOCK_BANK_DIR / "official.html"))


@app.get("/mock-bank/official.html")
async def official_bank():
    """Serve the official mock banking website."""
    return FileResponse(str(MOCK_BANK_DIR / "official.html"))


@app.get("/mock-bank/styles.css")
async def official_styles():
    """Serve the official mock banking stylesheet."""
    return FileResponse(str(MOCK_BANK_DIR / "styles.css"))


# ---------------------------------------------------------------------------
# Official Banking Page
# ---------------------------------------------------------------------------


@app.get("/mock-bank/fake.html")
async def fake_bank():
    """Serve the fake banking website (brand/domain mismatch)."""
    return FileResponse(str(ATTACK_DIR / "fake-bank.html"))


# ---------------------------------------------------------------------------
# Canary Probe Endpoints
# ---------------------------------------------------------------------------

@app.post("/canary/probe/start")
async def canary_start(request: Request):
    """Start a canary probe test."""
    data = await request.json()
    token = data.get("token")

    canary_state.update({
        "active": True,
        "token": token,
        "transmissionAttempted": False,
        "detected": False,
    })

    return {"status": "started", "token": token}


@app.post("/canary/probe/observe")
async def canary_observe(request: Request):
    """Report transmission attempt observation."""
    data = await request.json()
    canary_state["transmissionAttempted"] = data.get("transmissionAttempted", False)
    canary_state["detected"] = data.get("detected", False)

    return {"status": "observed", "transmissionAttempted": canary_state["transmissionAttempted"]}


@app.get("/canary/probe/status")
async def canary_status():
    """Get current canary probe status."""
    return {
        "status": "active" if canary_state["active"] else "idle",
        "token": canary_state["token"],
        "transmissionAttempted": canary_state["transmissionAttempted"],
        "detected": canary_state["detected"],
    }


# ---------------------------------------------------------------------------
# Simulated Attack Endpoints
# ---------------------------------------------------------------------------

# Attack 1: fetch() to collect OTP
@app.post("/attacks/fetch-collect")
async def fetch_collect(request: Request):
    """Simulated attacker endpoint collecting OTP via fetch."""
    # Return the canary token if it was sent
    return {"status": "collected", "token": canary_state.get("token")}


# Attack 2: XHR to exfiltrate
@app.post("/attacks/xhr-exfil")
async def xhr_exfil(request: Request):
    """Simulated attacker endpoint exfiltrating via XHR."""
    body = await request.json()
    return {"status": "exfiltrated", "data": body}


# Attack 3: sendBeacon
@app.post("/attacks/sendbeacon-exfil")
async def sendbeacon_exfil(request: Request):
    """Simulated attacker endpoint via sendBeacon."""
    form = await request.form()
    return {"status": "beacon_sent", "data": dict(form)}


# ---------------------------------------------------------------------------
# Brand Validation API
# ---------------------------------------------------------------------------

@app.get("/brand/{brand_id}")
async def brand_info(brand_id: str):
    """Get brand domain information."""
    brand = BRAND_REGISTRY.get(brand_id)
    if brand:
        return {"brandId": brand_id, ...brand}
    return {"error": "Brand not found"}, 404


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "x-ray-simulation"}


# ---------------------------------------------------------------------------
# Server Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
    )