/**
 * X-Ray Security Extension Popup - Plain JS with CDN scripts
 * All 7 screens implemented without React build dependency
 */

// Initialize Lucide icons on page load
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons()
})

// ---------------------------------------------------------------------------
// Core State
// ---------------------------------------------------------------------------

const state = {
  currentSite: 'demo-bank-a.example',
  protectionMode: 'monitoring',
  riskScore: 0,
  threatLevel: 'LOW',
  monitoringActive: true,
  strictProtection: false,
  privacyMode: false,
}

// Canary probe state (global for inline onclick handlers)
window.__canary_state = {
  status: 'idle',
  token: '',
  result: null,
  startProbe: function () {
    this.token = `XRAY_TEST_OTP_${Math.floor(10000 + Math.random() * 90000)}`
    this.status = 'running'
    this.result = null
    const self = this
    setTimeout(() => {
      self.status = 'detected'
      self.result = {
        tokenStatus: 'generated',
        observedApi: 'fetch',
        attemptedDestination: 'attacker.example/api/collect',
        transmissionAttempted: true,
        externalTransmissionBlocked: true,
        verdict: 'POTENTIAL EXFILTRATION ATTEMPT CONFIRMED',
        startedAt: Date.now(),
        finishedAt: Date.now() + 2000,
      }
    }, 1500)
  },
  reset: function () {
    this.status = 'idle'
    this.token = ''
    this.result = null
  },
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

function html(strings, ...values) {
  let result = strings[0]
  for (let i = 0; i < values.length; i++) {
    const value = values[i] !== undefined ? String(values[i]) : ''
    result += value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  }
  return result
}

function q(selector) {
  return document.querySelector(selector)
}

function createToggle({ label, value, onChange, description }) {
  const wrapper = document.createElement('div')
  wrapper.className = 'flex items-center justify-between p-4 bg-xray-card border border-xray-border rounded-xl'

  const labelWrapper = document.createElement('div')
  const labelEl = document.createElement('h3')
  labelEl.className = 'font-medium text-xray-text'
  labelEl.textContent = label
  labelWrapper.appendChild(labelEl)
  if (description) {
    const descEl = document.createElement('p')
    descEl.className = 'text-xs text-xray-muted mt-1'
    descEl.textContent = description
    labelWrapper.appendChild(descEl)
  }
  wrapper.appendChild(labelWrapper)

  const toggleWrapper = document.createElement('div')
  toggleWrapper.className = 'toggle-switch'
  const input = document.createElement('input')
  input.type = 'checkbox'
  input.checked = value
  input.addEventListener('change', (e) => onChange(e.target.checked))
  const slider = document.createElement('span')
  slider.className = 'toggle-slider'
  toggleWrapper.appendChild(input)
  toggleWrapper.appendChild(slider)
  wrapper.appendChild(toggleWrapper)

  return wrapper
}

// ---------------------------------------------------------------------------
// Event Row
// ---------------------------------------------------------------------------

function createEventRow({ type, title, domain, action, time }) {
  const typeConfigs = {
    blocked: { color: 'text-xray-danger', bg: 'bg-xray-danger/5' },
    warning: { color: 'text-xray-warn', bg: 'bg-xray-warn/5' },
    info: { color: 'text-xray-accent', bg: 'bg-xray-accent/5' },
  }
  const config = typeConfigs[type] || typeConfigs.info

  const row = document.createElement('div')
  row.className = `flex items-center gap-3 p-3 rounded-lg border border-xray-border ${config.bg}`

  const contentDiv = document.createElement('div')
  contentDiv.className = 'flex-1 min-w-0'

  const h4 = document.createElement('h4')
  h4.className = 'text-sm font-medium text-xray-text truncate'
  h4.textContent = title

  const p = document.createElement('p')
  p.className = 'text-xs text-xray-muted truncate'
  p.textContent = `${domain} · ${action}`

  contentDiv.appendChild(h4)
  contentDiv.appendChild(p)
  row.appendChild(contentDiv)

  const timeSpan = document.createElement('span')
  timeSpan.className = `text-xs font-medium ${config.color}`
  timeSpan.textContent = time
  row.appendChild(timeSpan)

  return row
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

function showPopup() {
  const root = q('#root')
  if (!root) return

  const {
    currentSite, protectionMode, riskScore, threatLevel,
    monitoringActive, strictProtection, privacyMode,
  } = state

  let statusLabel, statusClass
  if (protectionMode === 'strict') {
    statusLabel = 'STRICT ACTIVE'
    statusClass = 'bg-xray-accent2/10 text-xray-accent2 border border-xray-accent2/30'
  } else if (protectionMode === 'monitoring') {
    statusLabel = 'MONITORING'
    statusClass = 'bg-xray-warn/10 text-xray-warn border border-xray-warn/30'
  } else {
    statusLabel = 'UNAVAILABLE'
    statusClass = 'bg-xray-muted/10 text-xray-muted border border-xray-muted/30'
  }

  let riskClass
  if (riskScore >= 60) riskClass = 'bg-xray-danger'
  else if (riskScore >= 30) riskClass = 'bg-xray-warn'
  else riskClass = 'bg-xray-accent2'

  root.innerHTML = `
    <div class="w-[400px] h-[560px] p-6 bg-xray-bg border-t border-xray-border overflow-y-auto">
      <div class="flex items-center gap-3 mb-6">
        <svg class="w-8 h-8" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="32" height="32" rx="8" fill="#0a0f1a" stroke="#06b6d4" strokeWidth="2" />
          <path d="M8 8l16 16M24 8L8 24" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" />
        </svg>
        <span class="text-xl font-bold text-xray-text">X-Ray</span>
      </div>

      <div class="mb-6 p-3 bg-xray-card border border-xray-border rounded-lg">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-xray-muted uppercase tracking-wider font-semibold">Current Website</span>
        </div>
        <div class="flex items-center gap-2">
          <svg class="w-4 h-4 text-xray-muted" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>
          <span class="text-sm font-medium text-xray-text truncate max-w-[200px]">${currentSite}</span>
        </div>
      </div>

      <div class="mb-6 p-3 bg-xray-card border border-xray-border rounded-lg">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-xray-muted uppercase tracking-wider font-semibold">Protection Status</span>
          <span class="text-xs font-medium px-2 py-1 rounded ${statusClass}">${statusLabel}</span>
        </div>
        <div class="flex items-center gap-2">
          <svg class="w-4 h-4 ${protectionMode === 'strict' ? 'text-xray-accent2' : protectionMode === 'monitoring' ? 'text-xray-warn' : 'text-xray-muted'}" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2L15.09 8.26L22 9.27L17 15.14L18.18 21.02L12 17.77L5.82 21.02L7 15.14L2 9.27L8.91 8.26L12 2Z"/></svg>
          <span class="text-sm text-xray-text">${protectionMode === 'strict' ? 'Active threat interception' : protectionMode === 'monitoring' ? 'Behavioral monitoring active' : 'Protection unavailable - enable in settings'}</span>
        </div>
      </div>

      <div class="mb-6 p-3 bg-xray-card border border-xray-border rounded-lg">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-xray-muted uppercase tracking-wider font-semibold">Risk Score</span>
          <span class="text-xs font-medium px-2 py-1 rounded ${riskClass}">${riskScore}/100</span>
        </div>
        <div class="w-full bg-[#1e293b] h-2 rounded-full overflow-hidden mb-2">
          <div class="h-full transition-all duration-500 ${riskClass}" style="width: ${Math.min(riskScore, 100)}%"></div>
        </div>
        <span class="text-xs text-xray-muted">${threatLevel} RISK</span>
      </div>

      <div class="mt-6 pt-4 border-t border-xray-border">
        <button onclick="showScreen('dashboard')" class="w-full btn-primary flex items-center justify-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3 12l2-2m0 0l7-7 7 7M5 10l7 7-7 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
          Open Dashboard
        </button>
      </div>
    </div>
  `
}

function showDashboard() {
  const root = q('#root')
  if (!root) return

  const stats = {
    totalScans: 42,
    threatsBlocked: 3,
    canaryTests: 1,
    lastScan: 'Just now',
  }

  root.innerHTML = `
    <div class="w-[900px] h-[700px] bg-xray-bg border-xray-border border overflow-hidden flex flex-col">
      <!-- Header -->
      <div class="flex items-center justify-between px-6 py-4 border-b border-xray-border bg-[#0f172a]">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-xray-accent" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#0a0f1a" stroke="#06b6d4" strokeWidth="2" /><path d="M8 8l16 16M24 8L8 24" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" /></svg>
          <span class="text-xl font-bold text-xray-text">X-Ray Security Dashboard</span>
        </div>
        <div class="flex gap-2">
          <button onclick="showScreen('popup')" class="btn-secondary text-xs px-3 py-2">Dashboard</button>
          <button onclick="showScreen('forensics')" class="btn-secondary text-xs px-3 py-2">Forensics</button>
          <button onclick="showScreen('canary')" class="btn-secondary text-xs px-3 py-2">Canary Probe</button>
        </div>
      </div>

      <!-- Stats Row -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 p-6">
        <div class="bg-xray-card border border-xray-border rounded-xl p-5">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs text-xray-muted uppercase tracking-wider">Total Scans</span>
            <span class="text-2xl font-bold text-xray-text">${stats.totalScans}</span>
          </div>
        </div>
        <div class="bg-xray-card border border-xray-border rounded-xl p-5">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs text-xray-muted uppercase tracking-wider">Threats Blocked</span>
            <span class="text-2xl font-bold text-xray-danger">${stats.threatsBlocked}</span>
          </div>
        </div>
        <div class="bg-xray-card border border-xray-border rounded-xl p-5">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs text-xray-muted uppercase tracking-wider">Canary Tests</span>
            <span class="text-2xl font-bold text-xray-accent2">${stats.canaryTests}</span>
          </div>
        </div>
        <div class="bg-xray-card border border-xray-border rounded-xl p-5">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs text-xray-muted uppercase tracking-wider">Last Scan</span>
            <span class="text-2xl font-bold text-xray-muted">${stats.lastScan}</span>
          </div>
        </div>
      </div>

      <!-- Protection Overview -->
      <div class="bg-xray-card border border-xray-border rounded-xl p-6 my-6">
        <h3 class="text-lg font-bold text-xray-text mb-4">Protection Status</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-4 bg-[#1e293b] rounded-lg border border-xray-border">
            <svg class="w-5 h-5 text-xray-accent2 mb-2" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L15.09 8.26L22 9.27L17 15.14L18.18 21.02L12 17.77L5.82 21.02L7 15.14L2 9.27L8.91 8.26L12 2Z"/></svg>
            <h4 class="font-semibold text-xray-text">Basic Protection</h4>
            <p class="text-xs text-xray-muted mt-1">Behavioral monitoring active</p>
            <div class="mt-3">
              <span class="text-xs font-medium px-2 py-1 rounded bg-xray-accent2/10 text-xray-accent2 border border-xray-accent2/30">ACTIVE</span>
            </div>
          </div>
          <div class="p-4 bg-[#1e293b] rounded-lg border border-xray-border">
            <svg class="w-5 h-5 text-xray-warn mb-2" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L15.09 8.26L22 9.27L17 15.14L18.18 21.02L12 17.77L5.82 21.02L7 15.14L2 9.27L8.91 8.26L12 2Z"/></svg>
            <h4 class="font-semibold text-xray-text">Strict Interception</h4>
            <p class="text-xs text-xray-muted mt-1">Debugger API protection</p>
            <div class="mt-3">
              <span class="text-xs font-medium px-2 py-1 rounded bg-xray-muted/10 text-xray-muted border border-xray-muted/30">INACTIVE</span>
            </div>
          </div>
          <div class="p-4 bg-[#1e293b] rounded-lg border border-xray-border">
            <svg class="w-5 h-5 text-xray-muted mb-2" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10"/><path d="M8 14l2-2l4 4l2-2l4 4" fill="none" stroke="currentColor" strokeWidth="2"/><path d="M16 14l2-2l4 4l2-2l4 4" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
            <h4 class="font-semibold text-xray-text">Privacy Mode</h4>
            <p class="text-xs text-xray-muted mt-1">Local storage only</p>
            <div class="mt-3">
              <span class="text-xs font-medium px-2 py-1 rounded bg-xray-muted/10 text-xray-muted border border-xray-muted/30">INACTIVE</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent Activity -->
      <div class="bg-xray-card border border-xray-border rounded-xl p-6">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-bold text-xray-text">Recent Security Events</h3>
          <button class="text-xs text-xray-accent hover:text-xray-accent/80">View All</button>
        </div>
        <div class="space-y-3">
          ${[
            { type: 'blocked', title: 'Malicious domain blocked', domain: 'attacker.example', action: 'Blocked by DNR', time: '2 min ago' },
            { type: 'warning', title: 'Brand/domain mismatch detected', domain: 'fake-bank.example', action: 'Warning displayed', time: '15 min ago' },
            { type: 'info', title: 'OTP field detected', domain: 'demo-bank-a.example', action: 'Monitoring active', time: '45 min ago' },
            { type: 'info', title: 'Network monitoring started', domain: 'demo-bank-a.example', action: 'fetch API instrumented', time: '1 hr ago' },
          ].map(e => createEventRow(e)).join('')}
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="bg-xray-card border border-xray-border rounded-xl p-6">
        <h3 class="text-lg font-bold text-xray-text mb-4">Quick Actions</h3>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <button onclick="enableStrict()" class="btn-secondary w-full flex items-center gap-2 text-left">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L4.99 8.99L2 22l10-5 10 5-10 5z"/></svg>
            Enable Strict Protection
          </button>
          <button onclick="runCanary()" class="btn-secondary w-full flex items-center gap-2 text-left">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 5v14l11-5.5V5H8z"/></svg>
            Run Canary Probe
          </button>
          <button onclick="showScreen('history')" class="btn-secondary w-full flex items-center gap-2 text-left">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14h9l-1 8 9-9h-9l1-8z"/></svg>
            View Activity History
          </button>
          <button onclick="showScreen('settings')" class="btn-secondary w-full flex items-center gap-2 text-left">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3 13h2v8H3v-8zm18 0h2v8h-2v-8zm-9-9h2v5h-2v5H6v-5H3v5H2v-5H0v-5h2v-5h9v5H9v-5h2z"/></svg>
            Settings & Consent
          </button>
        </div>
      </div>
    </div>
  `
}

function showForensics() {
  const root = q('#root')
  if (!root) return

  const nodes = [
    { id: 'input-1', label: 'OTP Input Field', kind: 'sensitive_input', suspicious: true, metadata: { type: 'otp', selector: 'input[name="otp"]' } },
    { id: 'api-1', label: 'fetch()', kind: 'js_api', suspicious: true, metadata: { api: 'fetch', method: 'POST', url: 'https://attacker.example/api/collect' } },
    { id: 'req-1', label: 'Outgoing Request', kind: 'request', suspicious: true, metadata: { api: 'fetch', status: 'blocked', sizeHint: 256 } },
    { id: 'dest-1', label: 'attacker.example', kind: 'destination', suspicious: true, metadata: { hostname: 'attacker.example', threat: 'known_malicious' } },
  ]

  const edges = [
    { id: 'e1-2', source: 'input-1', target: 'api-1', suspicious: true, label: 'triggers' },
    { id: 'e2-3', source: 'api-1', target: 'req-1', suspicious: true, label: 'calls' },
    { id: 'e3-4', source: 'req-1', target: 'dest-1', suspicious: true, label: 'sends to' },
  ]

  const order = ['input-1', 'api-1', 'req-1', 'dest-1']

  root.innerHTML = `
    <div class="w-[900px] h-[700px] bg-xray-bg border-xray-border border overflow-hidden flex flex-col">
      <div class="flex items-center justify-between px-6 py-4 border-b border-xray-border bg-[#0f172a]">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-xray-accent" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#0a0f1a" stroke="#06b6d4" strokeWidth="2" /><path d="M8 8l16 16M24 8L8 24" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" /></svg>
          <span class="text-xl font-bold text-xray-text">Forensic Analysis</span>
        </div>
        <button onclick="showScreen('dashboard')" class="btn-secondary text-xs px-3 py-2">Refresh</button>
      </div>

      <div class="flex-1 p-4">
        <!-- Legend -->
        <div class="flex gap-4 mb-4 text-xs text-xray-muted">
          <div class="flex items-center gap-2">
            <div class="w-2 h-2 rounded-full bg-xray-danger"></div>
            <span>Suspicious</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="w-2 h-2 rounded-full bg-xray-accent2"></div>
            <span>Safe</span>
          </div>
        </div>

        <!-- Graph -->
        <div class="flex-1 bg-[#0f172a] rounded-xl border border-xray-border relative overflow-hidden">
          ${nodes.map((node, i) => {
            const idx = order.indexOf(node.id)
            return `
              <div key="${node.id}" class="absolute p-4 rounded-lg shadow-lg border cursor-pointer transition-all ${node.suspicious ? 'bg-[#450a0a] border border-xray-danger/30 shadow-[0_0_15px_rgba(239,68,68,0.15)]' : 'bg-[#0a1e1a] border border-xray-accent2/30 shadow-[0_0_15px_rgba(16,185,129,0.15)]'}" style="left: ${idx * 200 + 20}px; top: ${idx * 80 + 40}px;">
                <div class="flex items-center gap-2 mb-1">
                  <div class="w-2 h-2 rounded-full ${node.suspicious ? 'bg-xray-danger' : 'bg-xray-accent2'}"></div>
                  <span class="text-xs font-bold uppercase tracking-wider text-xray-muted">${node.kind.replace('_', ' ')}</span>
                </div>
                <h4 class="text-sm font-semibold ${node.suspicious ? 'text-xray-danger' : 'text-xray-accent2'}">${node.label}</h4>
                <div class="mt-2 text-[10px] text-xray-muted bg-[#000]/30 p-1 rounded">${JSON.stringify(node.metadata, null, 1).slice(0, 120)}...</div>
              </div>
            `
          }).join('')}
          ${edges.map((edge, i) => `<div key="${edge.id}" class="absolute" style="top: ${40 + i * 80}px; left: 220px; width: 160px; height: 2px; background: ${edge.suspicious ? '#ef4444' : '#10b981'}; opacity: 0.6;"></div>`).join('')}
        </div>
      </div>

      <div class="h-48 border-t border-xray-border bg-[#0f172a] p-4 overflow-y-auto">
        <h3 class="text-xs text-xray-muted uppercase tracking-wider mb-2">Selected Node Details</h3>
        <div class="space-y-2">
          <div class="flex justify-between text-sm">
            <span class="text-xray-muted">Element Type:</span>
            <span class="text-xray-text">OTP Input Field</span>
          </div>
          <div class="flex justify-between text-sm">
            <span class="text-xray-muted">API Used:</span>
            <span class="text-xray-text">fetch()</span>
          </div>
          <div class="flex justify-between text-sm">
            <span class="text-xray-muted">Destination:</span>
            <span class="text-xray-text text-xray-danger">attacker.example</span>
          </div>
          <div class="flex justify-between text-sm">
            <span class="text-xray-muted">Risk Contribution:</span>
            <span class="text-xray-text text-xray-danger">+30 points</span>
          </div>
          <div class="flex justify-between text-sm">
            <span class="text-xray-muted">Action Taken:</span>
            <span class="text-xray-text text-xray-accent2">Blocked</span>
          </div>
        </div>
      </div>
    </div>
  `
}

function showAlert() {
  const root = q('#root')
  if (!root) return

  const threat = {
    level: 'HIGH',
    score: 78,
    domain: 'fake-bank.example',
    explanation: 'This webpage claims to belong to DemoBank Alpha, but its registered domain does not match the verified official domain. An OTP field was detected, and a suspicious outgoing network request to attacker.example was observed shortly after interaction with the OTP field.',
    actions: [
      { label: 'Block and Protect', kind: 'primary', handler: 'enableStrict()' },
      { label: 'View Forensic Evidence', kind: 'secondary', handler: "showScreen('forensics')" },
      { label: 'Open Verified Website', kind: 'secondary', handler: 'showPopup()' },
      { label: 'Review Detection Explanation', kind: 'secondary', handler: '' },
    ],
  }

  root.innerHTML = `
    <div class="w-[600px] h-[700px] bg-xray-bg border-xray-border border overflow-hidden flex flex-col high-threat-card">
      <div class="flex items-center justify-between px-6 py-4 border-b border-xray-border bg-[#0f172a]">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-xray-danger" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="14"/><path d="M16 2L14 6l2 4-4 2-2-4L8 6l2-4L5 2" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
          <span class="text-xl font-bold text-xray-text">Security Alert</span>
        </div>
      </div>

      <div class="flex-1 p-6 space-y-6">
        <div class="text-center">
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-xray-danger/10 text-xray-danger border border-xray-danger/30">
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10"/><path d="M12 2v6l4 4" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
            <span class="font-bold text-xs uppercase">${threat.level} RISK</span>
          </div>
          <div class="text-3xl font-bold text-xray-text mt-2">${threat.score}/100</div>
          <div class="text-xs text-xray-muted mt-1">Threat Score</div>
        </div>

        <div class="bg-[#0a0f1a] border border-xray-border rounded-xl p-5">
          <h4 class="text-xs font-bold text-xray-muted uppercase tracking-wider mb-3">Suspicious Domain</h4>
          <div class="flex items-center gap-3">
            <svg class="w-5 h-5 text-xray-danger" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 2v6l4 4" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
            <div>
              <div class="text-xl font-mono text-xray-text break-all">${threat.domain}</div>
              <div class="text-xs text-xray-muted mt-1">Unverified domain - brand impersonation detected</div>
            </div>
          </div>
        </div>

        <div class="bg-[#0a0f1a] border border-xray-border rounded-xl p-5">
          <h4 class="text-xs font-bold text-xray-muted uppercase tracking-wider mb-3">Evidence</h4>
          <div class="space-y-3">
            <div class="flex items-start gap-3 p-2 rounded bg-[#000]/30">
              <svg class="w-4 h-4 text-xray-danger mt-1" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10"/><path d="M12 2v6l4 4" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
              <span class="text-sm text-xray-text leading-relaxed">Brand/domain mismatch - page claims DemoBank Alpha but domain doesn't match verified domain demo-bank-a.example</span>
            </div>
            <div class="flex items-start gap-3 p-2 rounded bg-[#000]/30">
              <svg class="w-4 h-4 text-xray-warn mt-1" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10"/><path d="M12 2v6l4 4" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
              <span class="text-sm text-xray-text leading-relaxed">OTP input field detected - sensitive authentication field present</span>
            </div>
            <div class="flex items-start gap-3 p-2 rounded bg-[#000]/30">
              <svg class="w-4 h-4 text-xray-accent mt-1" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><polygon points="12 2 15.09 8.26 22 9.27 17 15.14 18.18 21.02 12 17.77 5.82 21.02 7 15.14 2 9.27 8.91 8.26"/></svg>
              <span class="text-sm text-xray-text leading-relaxed">Outgoing request to attacker.example after OTP field interaction</span>
            </div>
            <div class="flex items-start gap-3 p-2 rounded bg-[#000]/30">
              <svg class="w-4 h-4 text-xray-muted mt-1" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              <span class="text-sm text-xray-text">API: fetch() - blocked before transmission</span>
            </div>
          </div>
        </div>

        <div class="bg-[#0a0f1a] border border-xray-border rounded-xl p-5">
          <h4 class="text-xs font-bold text-xray-muted uppercase tracking-wider mb-3">Detection Explanation</h4>
          <p class="text-sm text-xray-text leading-relaxed whitespace-pre-wrap">${threat.explanation}</p>
        </div>

        <div class="space-y-2">
          ${threat.actions.map((action, i) => `
            <button key="${i}" onclick="${action.handler}" class="w-full flex items-center justify-between px-4 py-3 rounded-lg border font-medium text-sm transition-all ${action.kind === 'primary' ? 'bg-xray-danger text-xray-text border-xray-danger/30 hover:bg-xray-danger/20' : 'bg-[#0f172a] text-xray-text border-xray-border hover:border-xray-accent'}">
              <span>${action.label}</span>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </button>
          `).join('')}
        </div>
      </div>
    </div>
  `
}

function showCanary() {
  const root = q('#root')
  if (!root) return

  const s = window.__canary_state
  const { status, token, result } = s

  root.innerHTML = `
    <div class="w-[600px] h-[700px] bg-xray-bg border-xray-border border overflow-hidden flex flex-col">
      <div class="flex items-center justify-between px-6 py-4 border-b border-xray-border bg-[#0f172a]">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-xray-accent2" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#0a0f1a" stroke="#06b6d4" strokeWidth="2" /><path d="M8 8l16 16M24 8L8 24" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" /></svg>
          <span class="text-xl font-bold text-xray-text">Canary Probe</span>
        </div>
      </div>

      <div class="flex-1 p-6 space-y-6">
        <div class="bg-[#0a0f1a] border border-xray-border rounded-xl p-5">
          <div class="flex items-center justify-between mb-3">
            <h4 class="font-bold text-xray-text">Probe Status</h4>
            <div class="w-8 h-8 rounded-full flex items-center justify-center ${status === 'running' ? 'bg-xray-warn/20 text-xray-warn border border-xray-warn/30 animate-pulse' : status === 'detected' ? 'bg-xray-danger/20 text-xray-danger border border-xray-danger/30' : status === 'safe' ? 'bg-xray-accent2/20 text-xray-accent2 border border-xray-accent2/30' : 'bg-xray-muted/20 text-xray-muted border border-xray-muted/30'}">
              <span>${status === 'running' || status === 'detected' || status === 'safe' ? '●' : '○'}</span>
            </div>
          </div>
          <div class="text-xs text-xray-muted uppercase tracking-wider mb-1">
            ${status === 'running' ? 'RUNNING - Monitoring network activity...' : status === 'detected' ? 'TRANSMISSION DETECTED - External transmission blocked' : status === 'safe' ? 'NO TRANSMISSION DETECTED - Safe' : 'IDLE - Ready to start probe'}
          </div>
        </div>

        <div class="bg-[#0a0f1a] border border-xray-border rounded-xl p-5">
          <h4 class="text-xs font-bold text-xray-muted uppercase tracking-wider mb-3">Synthetic Token Status</h4>
          <div class="flex items-start gap-3">
            <svg class="w-5 h-5 text-xray-muted" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10"/><path d="M8 14l2-2l4 4l2-2l4 4" fill="none" stroke="currentColor" strokeWidth="2"/></svg>
            <div>
              <div class="text-xs font-mono text-xray-text break-all">${token || 'No token generated yet'}</div>
              <div class="text-xs text-xray-muted mt-1">Never exposed to real credentials - synthetic only</div>
            </div>
          </div>
        </div>

        <div class="flex gap-3">
          <button onclick="window.__canary_state.startProbe()" disabled="${status === 'running'}" class="flex-1 btn-primary flex items-center justify-center gap-2 ${status === 'running' ? 'opacity-50 cursor-not-allowed' : ''}">
            ${status === 'running' ? 'Probe Running...' : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 5v14l11-5.5V5H8z"/></svg> Start Probe'}
          </button>
          <button onclick="window.__canary_state.reset()" class="btn-secondary px-4">Reset</button>
        </div>

        ${result ? `
          <div class="bg-[#0a0f1a] border border-xray-border rounded-xl p-5">
            <h4 class="text-xs font-bold text-xray-muted uppercase tracking-wider mb-3">Canary Probe Result</h4>
            <div class="space-y-3">
              <div class="flex justify-between text-sm p-2 rounded bg-[#000]/30">
                <span class="text-xray-muted">Synthetic Token:</span>
                <span class="text-xray-text font-mono">${result.tokenStatus}</span>
              </div>
              <div class="flex justify-between text-sm p-2 rounded bg-[#000]/30">
                <span class="text-xray-muted">Transmission Attempt:</span>
                <span class="text-xs font-medium ${result.transmissionAttempted ? 'text-xray-danger' : 'text-xray-accent2'}">${result.transmissionAttempted ? 'DETECTED' : 'NOT DETECTED'}</span>
              </div>
              <div class="flex justify-between text-sm p-2 rounded bg-[#000]/30">
                <span class="text-xray-muted">JavaScript API:</span>
                <span class="text-xray-text font-mono">${result.observedApi}</span>
              </div>
              <div class="flex justify-between text-sm p-2 rounded bg-[#000]/30">
                <span class="text-xray-muted">Destination:</span>
                <span class="text-xs font-medium text-xray-danger font-mono">${result.attemptedDestination}</span>
              </div>
              <div class="flex justify-between text-sm p-2 rounded bg-[#000]/30 border border-xray-danger/30">
                <span class="text-xray-muted">Verdict:</span>
                <span class="text-xs font-bold text-xray-danger">${result.verdict}</span>
              </div>
            </div>
          </div>
        ` : ''}
      </div>
    </div>
  `
}

function showSettings() {
  const root = q('#root')
  if (!root) return

  root.innerHTML = `
    <div class="w-[600px] h-[700px] bg-xray-bg border-xray-border border overflow-hidden flex flex-col">
      <div class="flex items-center justify-between px-6 py-4 border-b border-xray-border bg-[#0f172a]">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-xray-accent" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#0a0f1a" stroke="#06b6d4" strokeWidth="2" /><path d="M8 8l16 16M24 8L8 24" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" /></svg>
          <span class="text-xl font-bold text-xray-text">Settings & Consent</span>
        </div>
      </div>

      <div class="flex-1 overflow-y-auto p-6 space-y-6">
        <div class="bg-xray-card border border-xray-border rounded-xl p-6">
          <h3 class="text-lg font-bold text-xray-text mb-4">Protection Modes</h3>
          <div class="p-4 bg-[#1e293b] rounded-lg border border-xray-border mb-3">
            <div class="flex items-center justify-between mb-2">
              <h4 class="font-semibold text-xray-text">Basic Protection</h4>
            </div>
            <p class="text-xs text-xray-muted mt-1">Behavioral monitoring of all webpages - no consent needed for monitoring</p>
            <div class="mt-3">
              <span class="text-xs font-medium px-2 py-1 rounded bg-xray-accent2/10 text-xray-accent2 border border-xray-accent2/30">ACTIVE</span>
            </div>
          </div>
          <div class="p-4 bg-[#1e293b] rounded-lg border border-xray-border mb-3">
            <div class="flex items-center justify-between mb-2">
              <h4 class="font-semibold text-xray-text">Strict Protection Mode</h4>
            </div>
            <p class="text-xs text-xray-muted mt-1">Chrome Debugger API - blocks suspicious requests before transmission. Requires debugger permission.</p>
            <div class="mt-3">
              <span class="text-xs font-medium px-2 py-1 rounded bg-xray-muted/10 text-xray-muted border border-xray-muted/30">INACTIVE</span>
            </div>
          </div>
          <div class="mt-4 p-3 bg-[#0f172a] rounded-lg border border-xray-border">
            <p class="text-sm text-xray-text">⚠ Strict Protection Mode requires the "debugger" Chrome permission. If attachment fails, the extension falls back to monitoring-only mode and blocking is not active.</p>
          </div>
        </div>

        <div class="bg-xray-card border border-xray-border rounded-xl p-6">
          <h3 class="text-lg font-bold text-xray-text mb-4">Consent Management</h3>
          <div class="space-y-2">
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border">
              <div>
                <div class="font-medium text-xray-text">Extension Permissions</div>
                <div class="text-xs text-xray-muted mt-1">Allow X-Ray to monitor webpage behavior and access extension APIs</div>
              </div>
              <div class="toggle-switch">
                <input type="checkbox" checked disabled />
                <span class="toggle-slider"></span>
              </div>
            </div>
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border">
              <div>
                <div class="font-medium text-xray-text">Canary Probe Consent</div>
                <div class="text-xs text-xray-muted mt-1">Allow synthetic OTP testing against local mock banking environment</div>
              </div>
              <div class="toggle-switch">
                <input type="checkbox" disabled />
                <span class="toggle-slider"></span>
              </div>
            </div>
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border">
              <div>
                <div class="font-medium text-xray-text">External AI Processing</div>
                <div class="text-xs text-xray-muted mt-1">Send sanitized forensic evidence to external AI provider</div>
              </div>
              <div class="toggle-switch">
                <input type="checkbox" disabled />
                <span class="toggle-slider"></span>
              </div>
            </div>
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border">
              <div>
                <div class="font-medium text-xray-text">Safe Navigation</div>
                <div class="text-xs text-xray-muted mt-1">Require confirmation before navigating to official verified domains</div>
              </div>
              <div class="toggle-switch">
                <input type="checkbox" checked disabled />
                <span class="toggle-slider"></span>
              </div>
            </div>
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border">
              <div>
                <div class="font-medium text-xray-text">Cybercrime Report</div>
                <div class="text-xs text-xray-muted mt-1">Allow review and approval before submitting security reports</div>
              </div>
              <div class="toggle-switch">
                <input type="checkbox" disabled />
                <span class="toggle-slider"></span>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-xray-card border border-xray-border rounded-xl p-6">
          <h3 class="text-lg font-bold text-xray-text mb-4">Privacy Settings</h3>
          <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border mb-2">
            <span class="text-sm text-xray-text">Privacy Mode</span>
            <span class="text-xs font-medium text-xray-muted">INACTIVE</span>
          </div>
          <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border mb-2">
            <span class="text-sm text-xray-text">Local Storage Controls</span>
            <span class="text-xs font-medium text-xray-accent2">ACTIVE</span>
          </div>
        </div>

        <div class="bg-xray-card border border-xray-border rounded-xl p-6">
          <h3 class="text-lg font-bold text-xray-text mb-4">Monitoring Configuration</h3>
          <div class="space-y-2">
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border mb-2">
              <span class="text-sm text-xray-text">fetch() instrumentation</span>
              <span class="text-xs font-medium text-xray-accent2">ACTIVE</span>
            </div>
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border mb-2">
              <span class="text-sm text-xray-text">XMLHttpRequest instrumentation</span>
              <span class="text-xs font-medium text-xray-accent2">ACTIVE</span>
            </div>
            <div class="flex items-center justify-between p-3 bg-[#0f172a] rounded border border-xray-border">
              <span class="text-sm text-xray-text">sendBeacon() instrumentation</span>
              <span class="text-xs font-medium text-xray-accent2">ACTIVE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  `
}

function showHistory() {
  const root = q('#root')
  if (!root) return

  root.innerHTML = `
    <div class="w-[700px] h-[700px] bg-xray-bg border-xray-border border overflow-hidden flex flex-col">
      <div class="flex items-center justify-between px-6 py-4 border-b border-xray-border bg-[#0f172a]">
        <div class="flex items-center gap-3">
          <svg class="w-5 h-5 text-xray-accent" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#0a0f1a" stroke="#06b6d4" strokeWidth="2" /><path d="M8 8l16 16M24 8L8 24" stroke="#06b6d4" strokeWidth="2" strokeLinecap="round" /></svg>
          <span class="text-xl font-bold text-xray-text">Activity History</span>
        </div>
        <div class="flex gap-2">
          ${['all', 'LOW', 'MEDIUM', 'HIGH'].map(f => {
            const activeClass = f === 'all' ? 'bg-xray-accent text-xray-text border-xray-accent' : 'bg-[#0f172a] text-xray-muted border-xray-border hover:border-xray-accent'
            const buttonContent = '<button onclick="filterHistory(\'' + f + '\')" class="px-3 py-1 rounded text-xs font-medium border transition-all ' + activeClass + '">' + f + '</button>'
            return buttonContent
          }).join('')}
        }
      </div>

      <div class="flex-1 overflow-y-auto p-4">
        ${[
          { id: '1', time: '10:23 AM', site: 'attacker.example', type: 'blocked', level: 'HIGH', title: 'Malicious domain blocked by DNR' },
          { id: '2', time: '10:15 AM', site: 'fake-bank.example', type: 'warning', level: 'HIGH', title: 'Brand/domain mismatch detected' },
          { id: '3', time: '10:05 AM', site: 'demo-bank-a.example', type: 'info', level: 'LOW', title: 'OTP field detected - monitoring active' },
          { id: '4', time: '9:42 AM', site: 'demo-bank-b.example', type: 'blocked', level: 'MEDIUM', title: 'Suspicious form submission blocked' },
          { id: '5', time: '9:10 AM', site: 'demo-bank-a.example', type: 'info', level: 'LOW', title: 'Canary Probe completed - no transmission' },
        ].map(e => createEventRow(e)).join('')}
      </div>
    </div>
  `
}

// ---------------------------------------------------------------------------
// Global Functions
// ---------------------------------------------------------------------------

function showScreen(screen) {
  const root = q('#root')
  if (!root) return

  switch (screen) {
    case 'popup':
      showPopup()
      break
    case 'dashboard':
      showDashboard()
      break
    case 'forensics':
      showForensics()
      break
    case 'alert':
      showAlert()
      break
    case 'canary':
      showCanary()
      break
    case 'settings':
      showSettings()
      break
    case 'history':
      showHistory()
      break
  }
}

function enableStrict() {
  state.protectionMode = state.protectionMode === 'strict' ? 'monitoring' : 'strict'
  showScreen('dashboard')
}

function runCanary() {
  window.__canary_state.startProbe()
  showScreen('canary')
}

function filterHistory(filter) {
  showScreen('history')
}

// ---------------------------------------------------------------------------
// Initial load
// ---------------------------------------------------------------------------

showScreen('popup')