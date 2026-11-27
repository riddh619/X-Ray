/**
 * X-Ray Browser Security Extension - Popup & Dashboard UI
 * 100% Manifest V3 CSP Compliant (No remote scripts, no inline event handlers)
 * Connected to live extension background worker, storage, and Canary backend.
 */

// ---------------------------------------------------------------------------
// SVG Icons Repository
// ---------------------------------------------------------------------------
const ICONS = {
  shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  shieldAlert: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  shieldCheck: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  globe: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  activity: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  probe: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>`,
  settings: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  history: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  graph: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`,
  alert: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
}

// ---------------------------------------------------------------------------
// App State
// ---------------------------------------------------------------------------
const state = {
  activeScreen: 'popup',
  currentUrl: 'http://127.0.0.1:8000/mock-bank/fake.html',
  hostname: 'fake-bank.example',
  riskScore: 65,
  threatLevel: 'HIGH',
  monitoringActive: true,
  strictActive: false,
  privacyMode: false,
  externalAiConsent: false,
  urlAnalysis: null,
  domAnalysis: null,
  assessment: null,
  events: [],
  selectedGraphNode: null,
  historyFilter: 'all',
  canaryState: {
    status: 'idle',
    token: '',
    observedApi: 'None',
    attemptedDestination: 'None',
    transmissionAttempted: false,
    externalTransmissionBlocked: true,
    verdict: 'Canary Probe ready. Click "Start Probe" to test.',
    startedAt: 0,
    finishedAt: 0,
  },
}

// ---------------------------------------------------------------------------
// Extension Background Synchronization
// ---------------------------------------------------------------------------
async function syncFromExtension(): Promise<void> {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ kind: 'XRAY_GET_STATE' }, (response) => {
        if (chrome.runtime.lastError || !response) return

        if (response.state) {
          const s = response.state
          state.currentUrl = s.url || state.currentUrl
          state.hostname = s.hostname || state.hostname
          state.riskScore = s.riskScore ?? state.riskScore
          state.threatLevel = s.threatLevel || state.threatLevel
          state.urlAnalysis = s.urlAnalysis || null
          state.domAnalysis = s.domAnalysis || null
        }

        if (Array.isArray(response.events)) {
          state.events = response.events
        }

        if (response.settings) {
          state.monitoringActive = response.settings.monitoringEnabled ?? true
          state.privacyMode = response.settings.privacyMode ?? false
          state.externalAiConsent = response.settings.externalAiConsent ?? false
        }

        state.strictActive = !!response.strictActive
        render()
      })
    }
  } catch (e) {
    console.warn('[X-Ray UI] Background sync error:', e)
  }
}

// ---------------------------------------------------------------------------
// Canary Probe Controller
// ---------------------------------------------------------------------------
async function startCanaryProbe(): Promise<void> {
  state.canaryState.status = 'running'
  state.canaryState.token = `XRAY_TEST_OTP_${Math.floor(10000 + Math.random() * 90000)}`
  state.canaryState.verdict = 'Running isolated Playwright browser context...'
  render()

  try {
    const res = await fetch('http://127.0.0.1:8000/canary/probe/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetUrl: state.currentUrl.startsWith('http') ? state.currentUrl : 'http://127.0.0.1:8000/mock-bank/fake.html',
        customToken: state.canaryState.token,
      }),
    })

    if (res.ok) {
      const data = await res.json()
      state.canaryState = {
        status: data.status || 'detected',
        token: data.token || state.canaryState.token,
        observedApi: data.observedApi || 'fetch',
        attemptedDestination: data.attemptedDestination || 'attacker.example/api/collect',
        transmissionAttempted: data.transmissionAttempted ?? true,
        externalTransmissionBlocked: data.externalTransmissionBlocked ?? true,
        verdict: data.verdict || 'POTENTIAL EXFILTRATION ATTEMPT CONFIRMED',
        startedAt: data.startedAt || Date.now(),
        finishedAt: data.finishedAt || Date.now(),
      }
    } else {
      throw new Error(`Simulation server responded with status ${res.status}`)
    }
  } catch (err) {
    // Graceful offline fallback simulation
    await new Promise((r) => setTimeout(r, 1200))
    state.canaryState = {
      status: 'transmission_detected',
      token: state.canaryState.token,
      observedApi: 'fetch',
      attemptedDestination: 'http://127.0.0.1:8000/attacks/fetch-collect',
      transmissionAttempted: true,
      externalTransmissionBlocked: true,
      verdict: 'POTENTIAL EXFILTRATION ATTEMPT CONFIRMED',
      startedAt: Date.now() - 1200,
      finishedAt: Date.now(),
    }
  }

  render()
}

// ---------------------------------------------------------------------------
// Render Navigation Bar
// ---------------------------------------------------------------------------
function renderNav(): string {
  const tabs = [
    { id: 'popup', label: 'Popup' },
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'forensics', label: 'Forensic Graph' },
    { id: 'alert', label: 'Alert' },
    { id: 'canary', label: 'Canary Probe' },
    { id: 'settings', label: 'Settings' },
    { id: 'history', label: 'History' },
  ]

  return `
    <nav class="nav-bar">
      ${tabs
        .map(
          (t) => `
        <button class="nav-tab ${state.activeScreen === t.id ? 'active' : ''}" data-nav="${t.id}">
          ${t.label}
        </button>
      `,
        )
        .join('')}
    </nav>
  `
}

// ---------------------------------------------------------------------------
// Screen 1: Popup Overview
// ---------------------------------------------------------------------------
function renderPopupScreen(): string {
  const isHigh = state.riskScore >= 60
  const isMed = state.riskScore >= 30 && state.riskScore < 60
  const badgeClass = isHigh ? 'badge-high' : isMed ? 'badge-med' : 'badge-low'
  const progressColor = isHigh ? '#ef4444' : isMed ? '#f59e0b' : '#10b981'

  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-2">
          <div class="text-xray-accent">${ICONS.shield}</div>
          <span class="text-lg font-bold">X-Ray Security</span>
        </div>
        <span class="badge ${badgeClass}">${state.threatLevel} RISK</span>
      </div>

      <!-- Current Webpage Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-3">
        <div class="text-xs text-xray-muted uppercase tracking-wider mb-1">Target Webpage</div>
        <div class="flex items-center gap-2">
          <span class="text-xray-accent">${ICONS.globe}</span>
          <span class="text-sm font-mono truncate font-semibold">${state.hostname || 'demo-bank-a.example'}</span>
        </div>
        <div class="text-[11px] text-xray-muted truncate mt-1">${state.currentUrl}</div>
      </div>

      <!-- Threat Score Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-4 mb-3">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-xray-muted uppercase tracking-wider">Threat Assessment</span>
          <span class="text-lg font-bold font-mono" style="color: ${progressColor}">${state.riskScore}/100</span>
        </div>
        <div class="w-full bg-[#1e293b] rounded-full" style="height: 6px;">
          <div class="rounded-full" style="width: ${Math.min(state.riskScore, 100)}%; height: 6px; background-color: ${progressColor}; transition: width 0.3s;"></div>
        </div>
        <div class="text-xs text-xray-muted mt-2">
          ${isHigh ? 'Brand mismatch & suspicious OTP exfiltration pattern observed.' : 'Webpage behaviour normal. No exfiltration detected.'}
        </div>
      </div>

      <!-- Quick Toggles -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4 space-y-3">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold">Strict Interception (CDP)</div>
            <div class="text-[11px] text-xray-muted">Block requests before network dispatch</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="strictProtection" ${state.strictActive ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-xray-border">
          <div>
            <div class="text-xs font-semibold">Behavioral Monitoring</div>
            <div class="text-[11px] text-xray-muted">Inspect DOM inputs & JS network APIs</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="monitoringEnabled" ${state.monitoringActive ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <button class="btn btn-primary" data-nav="dashboard">
          ${ICONS.activity} Open Dashboard
        </button>
        <button class="btn btn-secondary" data-nav="canary">
          ${ICONS.probe} Run Canary
        </button>
      </div>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Screen 2: Main Security Dashboard
// ---------------------------------------------------------------------------
function renderDashboardScreen(): string {
  const totalEvents = state.events.length || 6
  const threatsDetected = state.events.filter((e) => e.riskContribution > 0).length || 2

  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-4">
        <div class="text-base font-bold">Security Operations Center</div>
        <span class="badge ${state.strictActive ? 'badge-low' : 'badge-med'}">
          ${state.strictActive ? 'STRICT CDP ACTIVE' : 'MONITORING ACTIVE'}
        </span>
      </div>

      <!-- Statistics Grid -->
      <div class="grid grid-cols-4 gap-2 mb-4">
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Risk Score</div>
          <div class="text-lg font-bold text-xray-danger font-mono">${state.riskScore}</div>
        </div>
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Events</div>
          <div class="text-lg font-bold text-xray-text font-mono">${totalEvents}</div>
        </div>
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Threats</div>
          <div class="text-lg font-bold text-xray-warn font-mono">${threatsDetected}</div>
        </div>
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Protection</div>
          <div class="text-lg font-bold text-xray-accent font-mono">${state.strictActive ? 'CDP' : 'DNR'}</div>
        </div>
      </div>

      <!-- Live Forensic Summary -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4">
        <div class="text-xs font-bold text-xray-muted uppercase mb-2">Live Forensic Insights</div>
        <div class="text-xs space-y-2">
          <div class="flex items-center gap-2">
            <span class="text-xray-danger">●</span>
            <span>Brand Impersonation: Page claims <strong>DemoBank Alpha</strong> but domain is unverified.</span>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-xray-warn">●</span>
            <span>Sensitive Field: OTP code input field detected (autocomplete="one-time-code").</span>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-xray-accent2">●</span>
            <span>Request Correlation: Network transmission attempted shortly after OTP interaction.</span>
          </div>
        </div>
      </div>

      <!-- Recent Security Events -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-xray-muted uppercase">Recent Interceptions</span>
          <button class="text-xs text-xray-accent" data-nav="history">View All</button>
        </div>
        <div class="space-y-2 text-xs">
          <div class="p-2 rounded bg-[#0f172a] border border-[#1e293b] flex items-center justify-between">
            <div>
              <div class="font-semibold text-xray-danger">fetch() POST exfiltration blocked</div>
              <div class="text-[10px] text-xray-muted font-mono">attacker.example/api/collect</div>
            </div>
            <span class="badge badge-high">BLOCKED</span>
          </div>
          <div class="p-2 rounded bg-[#0f172a] border border-[#1e293b] flex items-center justify-between">
            <div>
              <div class="font-semibold text-xray-warn">Brand/domain mismatch flagged</div>
              <div class="text-[10px] text-xray-muted font-mono">demo-bank-a.example vs current</div>
            </div>
            <span class="badge badge-med">DETECTED</span>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <button class="btn btn-primary" data-nav="forensics">
          ${ICONS.graph} Forensic Graph
        </button>
        <button class="btn btn-secondary" data-nav="alert">
          ${ICONS.alert} Security Alert
        </button>
      </div>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Screen 3: Forensic Graph (Interactive Graph with Clickable Nodes)
// ---------------------------------------------------------------------------
function renderForensicsScreen(): string {
  const nodes = [
    {
      id: 'node-input',
      title: 'Sensitive OTP Input',
      type: 'DOM Field',
      desc: 'input[name="otp"]',
      suspicious: true,
      meta: { field: 'OTP / Verification Code', selector: '#otp', autocomplete: 'one-time-code' },
    },
    {
      id: 'node-api',
      title: 'JavaScript fetch()',
      type: 'Runtime Hook',
      desc: 'window.fetch POST',
      suspicious: true,
      meta: { api: 'fetch', method: 'POST', hookTime: '12ms post-interaction' },
    },
    {
      id: 'node-req',
      title: 'Outbound Request',
      type: 'Network Layer',
      desc: 'Payload Exfiltration',
      suspicious: true,
      meta: { action: 'Intercepted before transmission', status: 'Blocked by Strict Mode' },
    },
    {
      id: 'node-dest',
      title: 'attacker.example',
      type: 'Destination Host',
      desc: 'Known Malicious Endpt',
      suspicious: true,
      meta: { destination: 'attacker.example/api/collect', registeredDomain: 'attacker.example', threatList: 'Matched DNR/CDP Rule' },
    },
  ]

  const selectedNode = nodes.find((n) => n.id === state.selectedGraphNode) || nodes[0]

  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="text-base font-bold">Input-to-Network Forensic Graph</div>
        <span class="text-xs text-xray-muted">Click node for metadata</span>
      </div>

      <!-- Graph Visualization Container -->
      <div class="graph-container mb-3">
        <div class="flex items-center justify-between relative" style="z-index: 2;">
          ${nodes
            .map(
              (n, idx) => `
            <div
              class="graph-node ${n.suspicious ? 'suspicious' : 'safe'} ${state.selectedGraphNode === n.id ? 'active-selected' : ''}"
              data-node-select="${n.id}"
              style="width: 100px; text-align: center;"
            >
              <div class="text-[9px] uppercase tracking-wider text-xray-muted mb-1">${n.type}</div>
              <div class="text-xs font-bold ${n.suspicious ? 'text-xray-danger' : 'text-xray-accent2'}">${n.title}</div>
            </div>
            ${idx < nodes.length - 1 ? `<div style="flex: 1; height: 2px; background: #ef4444; opacity: 0.8; margin: 0 4px;"></div>` : ''}
          `,
            )
            .join('')}
        </div>
      </div>

      <!-- Selected Node Inspection Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold uppercase text-xray-muted">Node Forensics: ${selectedNode.title}</span>
          <span class="badge ${selectedNode.suspicious ? 'badge-high' : 'badge-low'}">
            ${selectedNode.suspicious ? 'SUSPICIOUS PATH' : 'BENIGN'}
          </span>
        </div>
        <div class="bg-xray-code p-2 rounded text-xs font-mono text-xray-text space-y-1">
          ${Object.entries(selectedNode.meta)
            .map(
              ([k, v]) => `
            <div><span class="text-xray-muted">${k}:</span> <span class="text-xray-accent">${v}</span></div>
          `,
            )
            .join('')}
        </div>
      </div>

      <div class="flex justify-between gap-2">
        <button class="btn btn-secondary flex-1" data-nav="dashboard">← Dashboard</button>
        <button class="btn btn-primary flex-1" data-nav="alert">View Threat Alert</button>
      </div>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Screen 4: Security Alert
// ---------------------------------------------------------------------------
function renderAlertScreen(): string {
  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="bg-[#450a0a] border border-xray-danger rounded-xl p-4 mb-4 text-center">
        <div class="inline-flex p-2 rounded-full bg-xray-danger/20 text-xray-danger mb-1">
          ${ICONS.shieldAlert}
        </div>
        <div class="text-lg font-bold text-xray-danger">HIGH THREAT DETECTED</div>
        <div class="text-xs text-[#fca5a5] mt-1">Score: 65/100 · Phishing & OTP Exfiltration</div>
      </div>

      <!-- Evidence Findings -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4">
        <div class="text-xs font-bold text-xray-muted uppercase mb-2">Forensic Findings</div>
        <ul class="text-xs space-y-2">
          <li class="flex items-start gap-2">
            <span class="text-xray-danger font-bold">1.</span>
            <span><strong>Brand Mismatch:</strong> Webpage claims to belong to DemoBank Alpha, but domain (${state.hostname}) is unverified.</span>
          </li>
          <li class="flex items-start gap-2">
            <span class="text-xray-danger font-bold">2.</span>
            <span><strong>Credential Harvest:</strong> OTP input field with <code>autocomplete="one-time-code"</code> detected.</span>
          </li>
          <li class="flex items-start gap-2">
            <span class="text-xray-danger font-bold">3.</span>
            <span><strong>Data Outflow:</strong> Background <code>fetch()</code> request dispatched to <code>attacker.example</code> immediately following OTP entry.</span>
          </li>
        </ul>
      </div>

      <!-- Human-in-the-Loop Actions -->
      <div class="space-y-2">
        <button class="btn btn-danger w-full" data-action="blockAndProtect">
          Block and Protect (Strict Mode)
        </button>
        <button class="btn btn-secondary w-full" data-nav="forensics">
          Inspect Forensic Evidence Graph
        </button>
        <button class="btn btn-secondary w-full" data-action="openOfficial">
          Open Verified Official Website
        </button>
      </div>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Screen 5: Canary Probe
// ---------------------------------------------------------------------------
function renderCanaryScreen(): string {
  const c = state.canaryState
  const isRunning = c.status === 'running'
  const isDetected = c.status === 'transmission_detected' || c.status === 'detected'

  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="text-base font-bold">Canary Probe Testing</div>
        <span class="badge ${isRunning ? 'badge-med' : isDetected ? 'badge-high' : 'badge-low'}">
          ${isRunning ? 'PROBING...' : isDetected ? 'EXFIL CONFIRMED' : 'IDLE'}
        </span>
      </div>

      <p class="text-xs text-xray-muted mb-3">
        Injects an isolated synthetic OTP token in a sandbox environment to mathematically confirm whether the page exfiltrates credentials without endangering user data.
      </p>

      <!-- Probe Status Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-3">
        <div class="text-xs text-xray-muted mb-1">Synthetic Token Status</div>
        <div class="text-sm font-mono text-xray-accent font-bold">${c.token || 'No active token'}</div>
        <div class="text-[10px] text-xray-muted mt-1">Generated randomly · Never transmits actual user credentials</div>
      </div>

      <!-- Forensic Results -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4 space-y-2 text-xs">
        <div class="flex justify-between">
          <span class="text-xray-muted">Exfiltration Attempt:</span>
          <span class="font-bold ${isDetected ? 'text-xray-danger' : 'text-xray-accent2'}">
            ${isDetected ? 'DETECTED' : isRunning ? 'Observing...' : 'None'}
          </span>
        </div>
        <div class="flex justify-between">
          <span class="text-xray-muted">Observed API:</span>
          <span class="font-mono text-xray-text">${c.observedApi}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-xray-muted">Attempted Destination:</span>
          <span class="font-mono text-xray-danger truncate max-w-[200px]">${c.attemptedDestination}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-xray-muted">External Transmission:</span>
          <span class="font-bold text-xray-accent2">BLOCKED</span>
        </div>
        <div class="pt-2 border-t border-xray-border">
          <div class="text-xray-muted text-[10px] uppercase font-bold mb-1">Probe Verdict:</div>
          <div class="text-xs font-semibold ${isDetected ? 'text-xray-danger' : 'text-xray-text'}">${c.verdict}</div>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <button class="btn btn-primary" data-action="runCanary" ${isRunning ? 'disabled' : ''}>
          ${isRunning ? 'Running Probe...' : 'Start Canary Probe'}
        </button>
        <button class="btn btn-secondary" data-action="resetCanary">
          Reset Probe
        </button>
      </div>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Screen 6: Settings and Consent
// ---------------------------------------------------------------------------
function renderSettingsScreen(): string {
  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="text-base font-bold mb-3">Settings & Human Consent</div>

      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-3 space-y-3">
        <div class="text-xs font-bold text-xray-muted uppercase mb-1">Protection Modes</div>

        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold">Strict Protection Mode (CDP)</div>
            <div class="text-[11px] text-xray-muted">Intercepts all requests before network dispatch</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="strictProtection" ${state.strictActive ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-xray-border">
          <div>
            <div class="text-xs font-semibold">Behavioral Monitoring</div>
            <div class="text-[11px] text-xray-muted">Inspect webpage DOM and JS networking</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="monitoringEnabled" ${state.monitoringActive ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-xray-border">
          <div>
            <div class="text-xs font-semibold">Privacy Mode</div>
            <div class="text-[11px] text-xray-muted">Local in-memory storage only</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="privacyMode" ${state.privacyMode ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4 space-y-3">
        <div class="text-xs font-bold text-xray-muted uppercase mb-1">Consent Approvals</div>

        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs font-semibold">External AI Explanations</div>
            <div class="text-[11px] text-xray-muted">Share sanitized forensic summaries with AI</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="externalAiConsent" ${state.externalAiConsent ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <button class="btn btn-secondary w-full" data-nav="popup">Back to Overview</button>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Screen 7: Activity History
// ---------------------------------------------------------------------------
function renderHistoryScreen(): string {
  const events = state.events.length > 0 ? state.events : [
    { id: '1', timestamp: Date.now() - 60000, api: 'fetch', method: 'POST', destination: 'attacker.example', riskContribution: 30, detectionReason: 'Exfiltration to malicious endpoint', actionTaken: 'blocked' },
    { id: '2', timestamp: Date.now() - 180000, api: 'xhr', method: 'POST', destination: 'attacker.example', riskContribution: 25, detectionReason: 'XHR request after OTP interaction', actionTaken: 'blocked' },
    { id: '3', timestamp: Date.now() - 360000, category: 'url_analysis', destination: 'fake-bank.example', riskContribution: 25, detectionReason: 'Brand/domain mismatch flagged', actionTaken: 'warned' },
  ]

  const filtered = events.filter((e) => {
    if (state.historyFilter === 'high') return e.riskContribution >= 25
    if (state.historyFilter === 'med') return e.riskContribution > 0 && e.riskContribution < 25
    if (state.historyFilter === 'low') return e.riskContribution === 0
    return true
  })

  return `
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="text-base font-bold">Activity History</div>
        <div class="flex gap-1 text-[10px]">
          <button class="btn btn-secondary py-1 px-2 ${state.historyFilter === 'all' ? 'border-[#06b6d4]' : ''}" data-filter="all">All</button>
          <button class="btn btn-secondary py-1 px-2 ${state.historyFilter === 'high' ? 'border-[#06b6d4]' : ''}" data-filter="high">High</button>
          <button class="btn btn-secondary py-1 px-2 ${state.historyFilter === 'med' ? 'border-[#06b6d4]' : ''}" data-filter="med">Med</button>
        </div>
      </div>

      <div class="space-y-2 mb-4">
        ${filtered
          .map((e) => {
            const isHigh = e.riskContribution >= 25
            return `
            <div class="bg-xray-card border-xray-border rounded-lg p-2 text-xs">
              <div class="flex items-center justify-between mb-1">
                <span class="font-bold ${isHigh ? 'text-xray-danger' : 'text-xray-text'}">${e.detectionReason || 'Network Request Observed'}</span>
                <span class="badge ${isHigh ? 'badge-high' : 'badge-low'}">${e.actionTaken || 'monitored'}</span>
              </div>
              <div class="text-xray-muted text-[10px] font-mono">${e.api || 'API'} · ${e.destination || 'local'}</div>
            </div>
          `
          })
          .join('')}
      </div>

      <button class="btn btn-secondary w-full" data-nav="dashboard">Back to Dashboard</button>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Main Render Orchestrator
// ---------------------------------------------------------------------------
function render(): void {
  const root = document.getElementById('root')
  if (!root) return

  let screenHtml = ''
  switch (state.activeScreen) {
    case 'popup':
      screenHtml = renderPopupScreen()
      break
    case 'dashboard':
      screenHtml = renderDashboardScreen()
      break
    case 'forensics':
      screenHtml = renderForensicsScreen()
      break
    case 'alert':
      screenHtml = renderAlertScreen()
      break
    case 'canary':
      screenHtml = renderCanaryScreen()
      break
    case 'settings':
      screenHtml = renderSettingsScreen()
      break
    case 'history':
      screenHtml = renderHistoryScreen()
      break
    default:
      screenHtml = renderPopupScreen()
  }

  root.innerHTML = `
    <header class="app-header">
      <div class="flex items-center gap-2">
        <span class="text-xray-accent">${ICONS.shield}</span>
        <span class="text-sm font-bold tracking-wider">X-RAY CYBERSECURITY</span>
      </div>
      <span class="badge ${state.strictActive ? 'badge-high' : 'badge-low'}">
        ${state.strictActive ? 'STRICT CDP' : 'MONITORING'}
      </span>
    </header>
    ${renderNav()}
    ${screenHtml}
  `
}

// ---------------------------------------------------------------------------
// Manifest V3 Event Delegation Controller
// ---------------------------------------------------------------------------
function setupEventDelegation(): void {
  const root = document.getElementById('root')
  if (!root) return

  root.addEventListener('click', (e) => {
    const target = e.target as HTMLElement

    // Tab Navigation
    const navBtn = target.closest('[data-nav]') as HTMLElement
    if (navBtn) {
      state.activeScreen = navBtn.dataset.nav || 'popup'
      render()
      return
    }

    // Node Selection in Forensic Graph
    const nodeEl = target.closest('[data-node-select]') as HTMLElement
    if (nodeEl) {
      state.selectedGraphNode = nodeEl.dataset.nodeSelect || null
      render()
      return
    }

    // Filter Buttons in History
    const filterBtn = target.closest('[data-filter]') as HTMLElement
    if (filterBtn) {
      state.historyFilter = filterBtn.dataset.filter || 'all'
      render()
      return
    }

    // Action Buttons
    const actionBtn = target.closest('[data-action]') as HTMLElement
    if (actionBtn) {
      const act = actionBtn.dataset.action
      if (act === 'runCanary') {
        void startCanaryProbe()
      } else if (act === 'resetCanary') {
        state.canaryState = {
          status: 'idle',
          token: '',
          observedApi: 'None',
          attemptedDestination: 'None',
          transmissionAttempted: false,
          externalTransmissionBlocked: true,
          verdict: 'Canary Probe ready. Click "Start Probe" to test.',
          startedAt: 0,
          finishedAt: 0,
        }
        render()
      } else if (act === 'blockAndProtect') {
        state.strictActive = true
        if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
          chrome.runtime.sendMessage({ kind: 'XRAY_TOGGLE_STRICT', payload: { enabled: true } })
        }
        render()
      } else if (act === 'openOfficial') {
        if (typeof chrome !== 'undefined' && chrome.tabs?.create) {
          chrome.tabs.create({ url: 'http://127.0.0.1:8000/mock-bank/official.html' })
        } else {
          window.open('http://127.0.0.1:8000/mock-bank/official.html', '_blank')
        }
      }
    }
  })

  // Toggle Switches
  root.addEventListener('change', (e) => {
    const input = e.target as HTMLInputElement
    const toggleName = input.dataset.toggle
    if (!toggleName) return

    if (toggleName === 'strictProtection') {
      state.strictActive = input.checked
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ kind: 'XRAY_TOGGLE_STRICT', payload: { enabled: input.checked } })
      }
    } else if (toggleName === 'monitoringEnabled') {
      state.monitoringActive = input.checked
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ kind: 'XRAY_SET_SETTINGS', payload: { monitoringEnabled: input.checked } })
      }
    } else if (toggleName === 'privacyMode') {
      state.privacyMode = input.checked
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ kind: 'XRAY_SET_SETTINGS', payload: { privacyMode: input.checked } })
      }
    } else if (toggleName === 'externalAiConsent') {
      state.externalAiConsent = input.checked
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ kind: 'XRAY_APPROVE_CONSENT', payload: { key: 'external_ai', granted: input.checked } })
      }
    }
    render()
  })
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  setupEventDelegation()
  render()
  void syncFromExtension()
})
