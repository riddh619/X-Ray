# X-Ray: AI-Assisted Browser Security Extension

## Project Overview

**X-Ray** is an AI-assisted, local-first browser security extension designed to identify phishing websites, detect suspicious webpage behavior, and prevent sensitive information (passwords, OTP codes) from being transmitted to unauthorized destinations.

Unlike conventional phishing detectors that primarily depend on static URL blacklists and domain reputation, X-Ray investigates what a webpage actually does while running:
1. **Observes JavaScript API activity** (`fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, `WebSocket`) in the webpage's MAIN world at `document_start`.
2. **Inspects sensitive DOM elements** (`password`, OTP `autocomplete="one-time-code"`, forms, hidden iframes) in an ISOLATED content script world.
3. **Correlates user input interactions** with suspicious outgoing requests.
4. **Calculates a deterministic threat score (0–100)** with granular forensic breakdowns and zero double-counting.
5. **Intercepts malicious requests** via Declarative Net Request (DNR) and Chrome Debugger Protocol (CDP Fetch domain).
6. **Performs synthetic OTP Canary Probes** using an isolated Playwright browser context.
7. **Maintains Human-in-the-Loop workflows** for all critical protection actions.

### Core Philosophy
> *"Investigate autonomously. Explain transparently. Act with user control."*

---

## Technology Stack

- **Browser Extension:** Chrome Extension Manifest V3, WXT Framework, TypeScript, Chrome Storage API, Chrome Debugger API (CDP), Declarative Net Request API.
- **Frontend & UI/UX:** 100% Manifest V3 CSP Compliant (No remote CDNs, zero inline event handlers, custom cybersecurity dark theme, SVG iconography, interactive forensic graph).
- **Detection Engine:** TypeScript, Browser DOM APIs, JavaScript runtime instrumentation, Unicode UTS #39-compatible homoglyph detection, brand registry matching.
- **Simulation Environment:** Python 3.12, FastAPI, Playwright (isolated browser context for Canary Probes), HTML5, CSS3, JavaScript.
- **Test Framework:** Pytest, Pytest-Asyncio, HTTPX, Playwright Test Automation.

---

## Project Structure

```
X-Ray/
├── extension/                       # Chrome Manifest V3 Extension (WXT)
│   ├── .output/chrome-mv3/          # Built production extension for "Load Unpacked"
│   ├── entrypoints/
│   │   ├── background.ts            # Service worker (DNR, CDP, tab state, storage)
│   │   ├── content.ts               # ISOLATED-world script (DOM analysis, relay)
│   │   ├── main-world.content.ts    # MAIN-world script (fetch/XHR/sendBeacon hooks)
│   │   └── popup/
│   │       ├── index.html           # Popup root
│   │       ├── main.ts              # UI controller (7 screens, event delegation)
│   │       └── style.css            # Dark cybersecurity theme
│   ├── modules/
│   │   ├── url-analyzer.ts          # Homoglyph, multi-part TLD & brand detection
│   │   ├── dom-analyzer.ts          # OTP & password field discovery
│   │   ├── risk-engine.ts           # Deterministic 0-100 scoring model
│   │   ├── network-interceptor.ts   # DNR & CDP Fetch interception
│   │   ├── ai-explainer.ts          # Sanitized evidence explanation engine
│   │   └── approval-manager.ts      # Human-in-the-Loop consent manager
│   ├── data/
│   │   └── brand-registry.json      # Verified banking domain registry
│   ├── types/                       # Shared TypeScript interfaces
│   ├── wxt.config.ts                # WXT build configuration
│   └── package.json                 # Extension dependencies
│
├── simulation/                      # Controlled Mock Banking & Testing Environment
│   ├── server.py                    # FastAPI server & Playwright Canary Probe engine
│   ├── webpages/
│   │   ├── mock-bank/
│   │   │   ├── official.html        # Legitimate DemoBank Alpha login
│   │   │   ├── otp.html             # Legitimate OTP verification screen
│   │   │   └── styles.css           # Mock bank stylesheet
│   │   └── attacks/
│   │       ├── fake-bank.html       # Phishing page with 5 simulated attack vectors
│   │       └── tracker.html         # Hidden tracking frame test scenario
│   └── requirements.txt             # Python dependencies
│
├── tests/                           # Automated Verification Suite
│   ├── test_unit.py                 # Domain, homoglyph, DOM & risk engine unit tests
│   └── test_integration.py          # FastAPI routes & Playwright Canary Probe tests
│
├── package.json                     # Root scripts & orchestration
└── README.md                        # Documentation
```

---

## Installation & Setup

### Prerequisites
- **Google Chrome** (v120+ recommended)
- **Node.js** (v18+ or v24) & **npm**
- **Python** (v3.10+)

### 1. Install Extension Dependencies & Build Extension
```bash
cd extension
npm install
npm run build
```
The production extension bundle is generated in `extension/.output/chrome-mv3`.

### 2. Install Simulation Environment Dependencies
```bash
python -m pip install -r simulation/requirements.txt
python -m playwright install chromium
```

---

## How to Load the Extension in Google Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the upper-right corner.
3. Click **Load unpacked**.
4. In the folder picker, select:
   ```
   <WORKSPACE_PATH>/X-RAY/extension/.output/chrome-mv3
   ```
5. The **X-Ray** icon will appear in your Chrome toolbar. Pin it for easy access.

---

## How to Run the Controlled Simulation Environment

Start the simulation server:
```bash
cd simulation
python server.py
```
The server starts at `http://127.0.0.1:8000`:
- **Official Bank Portal:** `http://127.0.0.1:8000/mock-bank/official.html`
- **Fake Phishing Portal:** `http://127.0.0.1:8000/mock-bank/fake.html`
- **Health Check:** `http://127.0.0.1:8000/health`

---

## End-to-End Demonstration Workflow

### Step 1: Official Mock Bank (Safe Behavior)
1. Navigate to `http://127.0.0.1:8000/mock-bank/official.html`.
2. Click the X-Ray extension icon in the toolbar.
3. **Observation:** X-Ray detects the domain, registers legitimate banking inputs, and displays **0/100 LOW RISK**.
4. Enter credentials and click Continue to view the official OTP page (`/mock-bank/otp.html`).

### Step 2: Simulated Fake Banking Website (Phishing & Exfiltration)
1. Navigate to `http://127.0.0.1:8000/mock-bank/fake.html`.
2. Click the X-Ray extension icon.
3. **Observation:**
   - X-Ray detects the **brand/domain mismatch** (the page claims to be *DemoBank Alpha*, but is hosted on an unverified domain).
   - X-Ray identifies the sensitive **OTP input field** (`autocomplete="one-time-code"`).
   - The risk score increases immediately to **HIGH RISK** (65/100).
4. In the page, click **Submit Credentials**:
   - The simulated page attempts to exfiltrate the OTP code via `fetch()` to `http://127.0.0.1:8000/attacks/fetch-collect`.
   - X-Ray observes the sensitive input interaction and correlates it with the network dispatch.

### Step 3: Strict Protection Mode (CDP Interception)
1. Open the X-Ray popup and toggle **Strict Interception (CDP)** ON (or click "Block and Protect" in the Alert screen).
2. Chrome will display the native debugging banner indicating X-Ray has attached to the active tab.
3. Any subsequent malicious request to `attacker.example` or unauthorized endpoints is intercepted and aborted via the Chrome DevTools Protocol `Fetch.failRequest` (`net::ERR_BLOCKED_BY_CLIENT`).
4. If the debugger is closed or cancelled, X-Ray gracefully falls back to behavioral monitoring.

### Step 4: Forensic Graph Visualization
1. In the popup, click **Dashboard** → **Forensic Graph**.
2. An interactive chain displays:
   ```
   [Sensitive OTP Input] ──> [JavaScript fetch()] ──> [Outbound Request] ──> [attacker.example]
   ```
3. Suspicious paths are highlighted in **red**, benign paths in **green**.
4. Click on any node to view detailed forensic metadata in the inspection console.

### Step 5: Synthetic OTP Canary Probe Testing
1. In the popup, click **Canary Probe**.
2. Click **Start Canary Probe**.
3. **Execution:**
   - An isolated Playwright browser context launches in the backend.
   - A unique synthetic token is generated (e.g., `XRAY_TEST_OTP_94721`).
   - The probe populates the OTP field and triggers the submission in the sandbox.
   - All external network access is blocked; local routes are inspected.
   - The probe confirms that the webpage attempted to transmit the synthetic token via `fetch()`.
   - Result is reported:
     ```
     STATUS: TRANSMISSION DETECTED
     TOKEN: XRAY_TEST_OTP_94721
     OBSERVED API: fetch
     DESTINATION: http://127.0.0.1:8000/attacks/fetch-collect
     EXTERNAL TRANSMISSION: BLOCKED
     VERDICT: POTENTIAL EXFILTRATION ATTEMPT CONFIRMED
     ```
4. If tested against a legitimate page (`/mock-bank/otp.html`), the probe confirms `NO EXFILTRATION DETECTED`.

---

## Running the Automated Test Suite

Run the complete test suite (25 tests covering domain detection, homoglyphs, brand matching, DOM inputs, risk scoring, DNR rules, FastAPI routes, and Playwright Canary execution):

```bash
# Run all unit tests
pytest tests/test_unit.py -v

# Run all integration & Playwright tests
pytest tests/test_integration.py -v

# Run the entire test suite
pytest tests/ -v
```

---

## Security & Privacy Invariants

1. **Zero Credential Capture:** X-Ray only captures field metadata (type, ID, autocomplete attribute, name) and network metadata (destination, method, timestamp). Actual passwords, keystrokes, and genuine OTPs are never stored or logged.
2. **Local-First Analysis:** Detection and risk calculation operate locally in the browser. No external API key or paid third-party infrastructure is required.
3. **Strict Canary Isolation:** The Canary Probe operates in an isolated Playwright browser context with strict network route aborting. Synthetic tokens never reach real banking domains.
4. **Human-in-the-Loop:** Security actions (enabling strict mode, external AI evidence sharing, safe navigation redirection) require explicit user consent.
