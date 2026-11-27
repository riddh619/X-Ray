
# X-Ray: AI-Assisted Browser Security Extension

## Project Overview

X-Ray is a complete, AI-assisted browser security extension designed to identify phishing websites, detect suspicious webpage behavior, and prevent sensitive information such as passwords and OTPs from being transmitted to unauthorized destinations.

Unlike conventional phishing detectors that primarily depend on URL blacklists, X-Ray investigates what a webpage actually does while it is running. It combines deterministic forensic analysis with optional AI explanation layers to provide comprehensive browser security protection.

## Core Philosophy

"Investigate autonomously. Explain transparently. Act with user control."

## Five Core Capabilities

1. **Live Webpage Monitoring** - Continuous observation of DOM, network requests, and JavaScript API activity
2. **Behavior-Based Phishing Detection** - Domain identity analysis, homoglyph detection, brand mismatch detection
3. **Sensitive-Data Exfiltration Prevention** - OTP field detection, network request monitoring, correlation analysis
4. **Intelligent Browser-Level Protection** - Declarative Net Request + Chrome Debugger API interception
5. **Human-in-the-Loop Security Workflows** - Consent-based protection decisions, forensic evidence review

## Technology Stack

### Browser Extension
- **Framework**: WXT (Web Extension Toolkit)
- **Manifest**: V3
- **Language**: TypeScript + JavaScript
- **APIs**: chrome.storage, chrome.runtime, chrome.tabs, chrome.debugger, chrome.declarativeNetRequest

### Frontend
- **UI**: Plain JavaScript with CDN-based Tailwind CSS and Lucide icons
- **Visualization**: Simple DOM-based forensic graph (no external charting libraries)
- **Styling**: Tailwind CSS via CDN, custom CSS variables

### Detection Engine
- **Language**: TypeScript
- **Core**: Browser DOM APIs, URL API, tldts (registered domain extraction)
- **Confusable Detection**: Unicode UTS #39-compatible homoglyph detection
- **Risk Scoring**: Configurable deterministic engine with proper classification (LOW/MEDIUM/HIGH)

### Simulation Environment
- **Language**: Python
- **Framework**: FastAPI
- **Browser Automation**: Playwright (for Canary Probe tests)
- **Pages**: Official mock banking + fake banking with attack simulations

## Project Structure

```
X-Ray/
├── extension/                # Browser extension source
│   ├── entrypoints/          # Entry points for WXT
│   │   ├── background.ts     # Background service worker
│   │   ├── content.ts        # Content script (ISOLATED world)
│   │   ├── main-world.ts     # MAIN-world JavaScript instrumentation
│   │   ├── popup/            # Extension popup UI (7 screens)
│   │   │   ├── index.html    # Popup HTML
│   │   │   └── main.js       # Popup JS (CDN-based UI)
│   │   └── dashboard.tsx     # Dashboard component (TypeScript)
│   ├── modules/              # Detection engine modules
│   │   ├── url-analyzer.ts   # Domain identity analysis
│   │   ├── dom-analyzer.ts   # DOM sensitive input analysis
│   │   ├── runtime-monitor.ts# MAIN-world API instrumentation
│   │   ├── risk-engine.ts    # Deterministic risk scoring
│   │   ├── ai-explainer.ts   # AI explanation engine
│   │   ├── network-interceptor.ts # DNR + CDP protection
│   │   └── approval-manager.ts # Human-in-the-Loop consent
│   ├── types/                # Shared TypeScript interfaces
│   ├── data/                 # Brand registry and config
│   │   └── brand-registry.json
│   └── utils/                # Utility functions
│
├── simulation/               # Controlled mock banking environment
│   ├── server.py             # FastAPI simulation server
│   ├── webpages/
│   │   ├── mock-bank/        # Official mock banking page
│   │   │   └── official.html
│   │   └── attacks/          # Fake banking page with attacks
│   │       └── fake-bank.html
│   └── requirements.txt      # Python dependencies
│
├── package.json              # Root project config
├── extension/package.json    # WXT extension config
├── .gitignore               # Git ignore rules
└── README.md                # This file
```

## Installation

### Prerequisites

1. **Google Chrome** (latest version)
2. **Node.js** v18+ (for WXT build tools)
3. **Python** 3.10+ (for simulation server)

### Extension Installation

1. **Clone the repository** (or extract to a directory)
2. **Install dependencies**:
   ```bash
   cd X-RAY/extension
   npm install
   ```
3. **Start the simulation server**:
   ```bash
   cd X-RAY/simulation
   pip install -r requirements.txt
   python server.py
   ```
   The server will run at `http://127.0.0.1:8000`

4. **Load the extension in Chrome**:
   - Open `chrome://extensions/`
   - Enable **Developer Mode** (toggle switch in upper right)
   - Click **Load Unpacked**
   - Select the `X-RAY/extension` directory

5. **Verify installation**:
   - The X-Ray icon should appear in Chrome's toolbar
   - Click the icon to open the popup
   - The extension will automatically analyze the current page

### Simulation Server Usage

Start the server:
```bash
cd X-RAY/simulation
python server.py
```

The server provides these endpoints:

- `GET /` - Official mock banking page (demo-bank-a.example)
- `GET /mock-bank/official.html` - Official mock banking page
- `GET /mock-bank/fake.html` - Fake banking page (brand/domain mismatch)
- `GET /attacks/fetch-collect` - Simulated attacker endpoint (fetch)
- `GET /attacks/xhr-exfil` - Simulated attacker endpoint (XHR)
- `GET /attacks/sendbeacon-exfil` - Simulated attacker endpoint (sendBeacon)
- `POST /canary/probe/start` - Start Canary Probe test
- `POST /canary/probe/observe` - Report transmission observation
- `GET /canary/probe/status` - Get Canary Probe status
- `GET /brand/{brand_id}` - Get brand domain info

## How to Use X-Ray

### 1. Basic Monitoring

1. Navigate to any webpage
2. Click the X-Ray extension icon
3. The popup will display:
   - Current website URL
   - Protection status (Monitoring/Strict/UNAVAILABLE)
   - Risk score (0-100)
   - Threat level (LOW/MEDIUM/HIGH)

### 2. Detecting Phishing Websites

1. Open the fake banking page: `http://127.0.0.1:8000/mock-bank/fake.html`
2. X-Ray will automatically:
   - Analyze the domain and detect brand/domain mismatch
   - Identify sensitive input fields (password, OTP)
   - Monitor JavaScript API activity (fetch, XHR, sendBeacon)
   - Calculate risk score based on detected indicators

3. The risk score should reflect the brand mismatch and OTP field presence

### 3. Canary Probe - Synthetic OTP Testing

1. Ensure Canary Probe consent is enabled in Settings
2. Click the **Canary Probe** screen in the popup
3. Click **Start Probe**
4. The probe will:
   - Generate a synthetic OTP token: `XRAY_TEST_OTP_94721`
   - Trigger the fake banking page's OTP submission
   - Attempt to transmit the token to `attacker.example`
   - Block external transmission (when Strict Protection Mode active)
   - Display the result:
     - **Transmission Detected** + **Blocked** = Potential exfiltration confirmed
     - **No Transmission** = Safe page behavior

### 4. Strict Protection Mode

1. Enable **Strict Protection** in the Settings screen
2. The extension will attempt to attach Chrome's Debugger API to the active tab
3. If successful:
   - All network requests pass through interception analysis
   - Suspicious requests are blocked before transmission
   - "STRICT ACTIVE" status displayed
4. If debugger permission unavailable:
   - Extension falls back to monitoring-only mode
   - Status shows "UNAVAILABLE" with explanation
   - User can enable basic monitoring instead

### 5. Viewing Forensic Evidence

1. Navigate to a suspicious website
2. Click **Forensics** in the popup
3. View the forensic graph showing:
   - Sensitive input field → JavaScript API → Outgoing Request → Destination Domain
   - Suspicious paths highlighted in red
   - Safe paths in green
4. Click nodes to inspect metadata
5. View the detection explanation with contribution breakdown

### 6. Consent Management

The extension respects user autonomy through categorized consent:

- **Extension Permissions** - Required for monitoring to function
- **Canary Probe** - Required before synthetic OTP testing
- **External AI** - Optional, requires explicit consent before sending sanitized forensic evidence to external providers
- **Safe Navigation** - Optional confirmation before navigating to verified domains
- **Cybercrime Report** - Optional approval before submitting security reports

Consent can be managed in the **Settings** screen of the popup.

## Features Implemented

### Detection Capabilities

✅ **Domain Analysis**:
- Homoglyph/confusable character detection (Unicode UTS #39)
- Mixed-script domain detection (Latin + Cyrillic + Greek etc.)
- IP address detection in hostname
- Punycode/IDN encoding detection
- Suspicious URL pattern detection
- Brand/domain mismatch against local registry

✅ **DOM Analysis**:
- Password field detection
- OTP field detection (autocomplete="one-time-code", name/id patterns)
- Email and username field detection
- Authentication form analysis (external action detection)
- Hidden iframe detection (display:none, zero-sized)
- Suspicious embedded script source detection

✅ **Runtime Monitoring** (MAIN-world instrumentation):
- fetch() API observation
- XMLHttpRequest observation
- sendBeacon() observation
- WebSocket connection monitoring
- Sensitive field interaction correlation

✅ **Risk Scoring Engine**:
- Deterministic scoring with configurable weights
- Classification: LOW (0-29), MEDIUM (30-59), HIGH (60-100)
- Proper handling: OTP field alone cannot cause HIGH verdict
- No double-counting of correlated evidence
- Full explanation of every risk contribution

### Protection Mechanisms

✅ **Declarative Net Request (DNR)**:
- Blocks known malicious domains
- Always active, no user permission required
- Rules loaded from local configuration

✅ **Chrome Debugger API (Strict Mode)**:
- Optional interception via debugger attachment
- Fetch domain enable + requestPaused handling
- Request inspection, continue, or fail
- Graceful fallback to monitoring if debugger unavailable
- User consent required for debugger permission

✅ **Canary Probe**:
- Synthetic OTP testing in isolated environment
- User-initiated, consent-required
- Safe detection without real credential exposure
- Blocks external transmission in controlled environment

### User Interface

✅ **7 Complete Screens**:
1. **Extension Popup** - Current site, protection status, risk score, toggles
2. **Main Dashboard** - Stats, protection overview, recent activity, quick actions
3. **Forensic Analysis** - Interactive graph (input→API→request→destination)
4. **Security Alert** - Threat classification, evidence, explanation, actions
5. **Canary Probe** - Synthetic OTP testing workflow
6. **Settings & Consent** - Protection modes, consent management, privacy settings
7. **Activity History** - Chronological forensic events, filter by threat level

✅ **Design Direction**:
- Dark navy/black background with cybersecurity aesthetic
- Blue and green accents, red threat indicators
- Clean typography, professional cards
- Subtle gradients, responsive layouts
- Lucide icons throughout
- Smooth but restrained animations

### AI Explanation

✅ **Deterministic Template Engine** (primary, no API key required):
- Clear English explanations of threat findings
- Template-based with placeholders for Hindi and Kannada extension
- Never sends passwords or OTPs to external providers

✅ **Optional External AI** (consent-required):
- OpenAI or Anthropic API through environment variable
- Only sends sanitized evidence (no credentials/OTPs)
- User must explicitly consent before sharing
- LLM explains evidence and recommends actions
- Never allows LLM to approve or execute security actions

## Testing

### Unit Tests

The project includes unit tests for core modules. Run tests:

```bash
cd X-RAY
npm test
```

Or run specific test suites:
```bash
npm run test:unit    # Unit tests
npm run test:integration  # Integration tests
```

### Manual Verification

Test the complete workflow:

1. **Domain detection**:
   - Official mock banking domain: Should show LOW risk, verified brand
   - Lookalike domain: Should show HIGH risk, homoglyph/mismatch detected
   - Homoglyph domain: Should detect confusable characters
   - Unknown domain: Basic analysis displayed

2. **DOM detection**:
   - Page with OTP field: Should detect OTP field, +5 points
   - Page with password field: Should detect password field
   - Form with external action: Should detect +10 points
   - Hidden iframe: Should detect +10 points

3. **Runtime monitoring**:
   - Navigate to fake banking page
   - Submit OTP → Should observe fetch/XHR/sendBeacon events
   - Correlation with sensitive field interaction should trigger +30 points

4. **Protection**:
   - Known malicious domain: Should be blocked by DNR
   - Strict Protection + suspicious request: Should be blocked by CDP
   - Legitimate third-party: Should be allowed
   - Debugger unavailable: Should fall back to monitoring

5. **Canary Probe**:
   - Start probe → Generate synthetic token
   - Trigger OTP exfiltration → Should detect transmission
   - Block external transmission → Should show "Blocked"
   - No attack scenario → Should show "No transmission detected"

6. **User Experience**:
   - Popup loads and displays current site
   - Dashboard loads with stats
   - Risk score updates with page analysis
   - Forensic graph updates with actual events
   - Consent workflow operates correctly
   - Activity history persists across sessions

## Limitations

### Known Constraints

1. **MAIN-world sandboxing**: JavaScript API instrumentation runs in the webpage's MAIN world, which is bypassable. This provides detection capability but not absolute network visibility. Events must be validated - never trust raw MAIN-world events unconditionally.

2. **Debugger permission dependency**: Strict Protection Mode requires the `debugger` Chrome permission. If attachment fails (user denies, extension not granted), the extension falls back to monitoring-only mode. Blocking is not active in this mode.

3. **Domain registry is local**: The brand/domain matching uses a local JSON registry. In production, this should be expanded with real verified banking domains. Currently contains 3 example brands.

4. **Cannot intercept all network traffic**: The MAIN-world monkey-patching approach cannot observe all browser communication mechanisms (e.g., some WebSocket implementations, background sync, etc.). Clearly distinguish between observed API activity and browser-confirmed network requests.

5. **No real credential collection**: By design - the extension never collects, stores, or transmits actual passwords, OTP values, or sensitive form contents.

6. **Simulation environment only**: The mock banking environment and attack simulations are for demonstration and testing purposes only. They do not represent real banking websites or infrastructure.

7. **AI explanation optional**: The deterministic template engine works without an external API. The optional LLM integration requires user consent and an API key environment variable.

8. **Browser compatibility**: Tested on Chrome (Chromium-based browsers). Firefox and Edge may have different API availability.

## Commands to Run the Project

```bash
# 1. Install extension dependencies
cd X-RAY/extension
npm install

# 2. Start the simulation server
cd X-RAY/simulation
pip install -r requirements.txt
python server.py

# 3. Load extension in Chrome
#   - chrome://extensions/ → Developer Mode → Load Unpacked → select extension/

# 4. Run the app
#   - Open Chrome, navigate to any page
#   - Click X-Ray icon to open popup
#   - Go to http://127.0.0.1:8000/mock-bank/official.html (safe)
#   - Go to http://127.0.0.1:8000/mock-bank/fake.html (test detection)

# 5. Unit tests
cd X-RAY/extension
npm test

# 6. Build the extension
npm run build

# 7. Zip for distribution
npm run zip
```

## Troubleshooting

### Common Issues

1. **Extension won't load**:
   - Ensure you're loading the correct directory (`extension/`, not `X-RAY/`)
   - Check that Developer Mode is enabled
   - Verify `manifest.json` is valid (WXT generates this automatically)

2. **Popup shows "UNAVAILABLE" for Strict Protection**:
   - This means the Chrome Debugger permission could not be obtained
   - Enable the permission or use Basic Protection (monitoring only)
   - Check chrome://extensions/permissions for debugger access

3. **No events being detected**:
   - Ensure you're testing against the fake banking page (`/mock-bank/fake.html`)
   - The official page uses legitimate behavior (no malicious exfiltration)
   - Try submitting the OTP form to trigger API activity

4. **Canary Probe shows "No transmission detected"**:
   - Ensure you're on the fake banking page, not the official page
   - The fake page's OTP form triggers exfiltration via fetch()
   - The official page does not have malicious behavior

5. **Risk score seems too low/high**:
   - The scoring weights are configurable in the background script
   - Default weights: known malicious +40, homoglyph +25, brand mismatch +25, etc.
   - OTP field alone adds only +5 points (cannot cause HIGH verdict alone)

6. **Simulation server won't start**:
   - Ensure Python 3.10+ is available
   - Check that port 8000 is not already in use
   - Verify `pip install -r requirements.txt` completed successfully

### Getting Help

- Review the `docs/` directory for additional documentation
- Check the console (`F12` → Console) for extension logs
- Review `extension/types/index.ts` for TypeScript interfaces
- Examine `extension/modules/` for module documentation

## Security and Privacy

### What X-Ray Does NOT Do

- ❌ Never collects real passwords, OTPs, or sensitive form contents
- ❌ Never transmits actual credentials to any external service
- ❌ Never stores forensic data outside the browser (chrome.storage.local)
- ❌ Never claims absolute protection against all phishing techniques
- ❌ Never fabricates detection results
- ❌ Does not ask user to approve every network request

### What X-Ray DOES Do

- ✅ Local-first risk analysis (no external dependencies required)
- ✅ Explicit consent for external AI processing
- ✅ Strict isolation for Canary Probe (no external network access during tests)
- ✅ Proper permission handling with clear indication of active status
- ✅ Graceful error handling and fallback modes
- ✅ Clear distinction between monitoring active and strict interception active
- ✅ No false "Protected" status when only monitoring
- ✅ Human-in-the-Loop approval for security actions

### Privacy by Design

- All forensic data stored in `chrome.storage.local`
- No external transmission unless user consents to external AI
- Canary Probe runs in isolated environment with aborted external requests
- Brand registry uses example domains only (no real banking data)
- Minimal permissions requested (activeTab, storage, scripting, debugger optional)
- Message validation from content scripts MAIN world
- Safe handling of malformed URLs and edge cases

## Final Deliverables Checklist

- ✅ Complete source code (all frontend, extension, detection engine, simulation, tests)
- ✅ Browser extension build (production directory loadable via chrome://extensions)
- ✅ Local simulation environment (official + fake mock banking pages)
- ✅ Canary Probe (functional synthetic OTP testing workflow)
- ✅ Security dashboard (functioning interface connected to actual extension events)
- ✅ Automated tests (unit tests for core modules)
- ✅ README.md (project overview, architecture, installation, usage, limitations)
- ✅ Final implementation report (features, test results, commands, limitations)

## Acknowledgments

- WXT framework for extension development abstraction
- Tailwind CSS for styling methodology
- Lucide for icon system
- FastAPI for simulation server simplicity
- Playwright for browser automation capabilities
- Chrome Extension APIs for security capabilities
=======
# X-Ray
>>>>>>> 07b3a3619fd464ba3f2565a00c39ac0ca9ca2350
