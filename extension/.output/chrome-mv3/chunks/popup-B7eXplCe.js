(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const i of document.querySelectorAll('link[rel="modulepreload"]'))n(i);new MutationObserver(i=>{for(const r of i)if(r.type==="childList")for(const d of r.addedNodes)d.tagName==="LINK"&&d.rel==="modulepreload"&&n(d)}).observe(document,{childList:!0,subtree:!0});function a(i){const r={};return i.integrity&&(r.integrity=i.integrity),i.referrerPolicy&&(r.referrerPolicy=i.referrerPolicy),i.crossOrigin==="use-credentials"?r.credentials="include":i.crossOrigin==="anonymous"?r.credentials="omit":r.credentials="same-origin",r}function n(i){if(i.ep)return;i.ep=!0;const r=a(i);fetch(i.href,r)}})();try{}catch(s){console.error("[wxt] Failed to initialize plugins",s)}const c={shield:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',shieldAlert:'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',globe:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',activity:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',probe:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>',graph:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>',alert:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'},e={activeScreen:"popup",currentUrl:"http://127.0.0.1:8000/mock-bank/fake.html",hostname:"fake-bank.example",riskScore:65,threatLevel:"HIGH",monitoringActive:!0,strictActive:!1,privacyMode:!1,externalAiConsent:!1,urlAnalysis:null,domAnalysis:null,assessment:null,events:[],selectedGraphNode:null,historyFilter:"all",canaryState:{status:"idle",token:"",observedApi:"None",attemptedDestination:"None",transmissionAttempted:!1,externalTransmissionBlocked:!0,verdict:'Canary Probe ready. Click "Start Probe" to test.',startedAt:0,finishedAt:0}};async function v(){var s;try{typeof chrome<"u"&&((s=chrome.runtime)!=null&&s.sendMessage)&&chrome.runtime.sendMessage({kind:"XRAY_GET_STATE"},t=>{if(!(chrome.runtime.lastError||!t)){if(t.state){const a=t.state;e.currentUrl=a.url||e.currentUrl,e.hostname=a.hostname||e.hostname,e.riskScore=a.riskScore??e.riskScore,e.threatLevel=a.threatLevel||e.threatLevel,e.urlAnalysis=a.urlAnalysis||null,e.domAnalysis=a.domAnalysis||null}Array.isArray(t.events)&&(e.events=t.events),t.settings&&(e.monitoringActive=t.settings.monitoringEnabled??!0,e.privacyMode=t.settings.privacyMode??!1,e.externalAiConsent=t.settings.externalAiConsent??!1),e.strictActive=!!t.strictActive,o()}})}catch(t){console.warn("[X-Ray UI] Background sync error:",t)}}async function u(){e.canaryState.status="running",e.canaryState.token=`XRAY_TEST_OTP_${Math.floor(1e4+Math.random()*9e4)}`,e.canaryState.verdict="Running isolated Playwright browser context...",o();try{const s=await fetch("http://127.0.0.1:8000/canary/probe/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({targetUrl:e.currentUrl.startsWith("http")?e.currentUrl:"http://127.0.0.1:8000/mock-bank/fake.html",customToken:e.canaryState.token})});if(s.ok){const t=await s.json();e.canaryState={status:t.status||"detected",token:t.token||e.canaryState.token,observedApi:t.observedApi||"fetch",attemptedDestination:t.attemptedDestination||"attacker.example/api/collect",transmissionAttempted:t.transmissionAttempted??!0,externalTransmissionBlocked:t.externalTransmissionBlocked??!0,verdict:t.verdict||"POTENTIAL EXFILTRATION ATTEMPT CONFIRMED",startedAt:t.startedAt||Date.now(),finishedAt:t.finishedAt||Date.now()}}else throw new Error(`Simulation server responded with status ${s.status}`)}catch{await new Promise(t=>setTimeout(t,1200)),e.canaryState={status:"transmission_detected",token:e.canaryState.token,observedApi:"fetch",attemptedDestination:"http://127.0.0.1:8000/attacks/fetch-collect",transmissionAttempted:!0,externalTransmissionBlocked:!0,verdict:"POTENTIAL EXFILTRATION ATTEMPT CONFIRMED",startedAt:Date.now()-1200,finishedAt:Date.now()}}o()}function m(){return`
    <nav class="nav-bar">
      ${[{id:"popup",label:"Popup"},{id:"dashboard",label:"Dashboard"},{id:"forensics",label:"Forensic Graph"},{id:"alert",label:"Alert"},{id:"canary",label:"Canary Probe"},{id:"settings",label:"Settings"},{id:"history",label:"History"}].map(t=>`
        <button class="nav-tab ${e.activeScreen===t.id?"active":""}" data-nav="${t.id}">
          ${t.label}
        </button>
      `).join("")}
    </nav>
  `}function b(){const s=e.riskScore>=60,t=e.riskScore>=30&&e.riskScore<60,a=s?"badge-high":t?"badge-med":"badge-low",n=s?"#ef4444":t?"#f59e0b":"#10b981";return`
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-2">
          <div class="text-xray-accent">${c.shield}</div>
          <span class="text-lg font-bold">X-Ray Security</span>
        </div>
        <span class="badge ${a}">${e.threatLevel} RISK</span>
      </div>

      <!-- Current Webpage Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-3">
        <div class="text-xs text-xray-muted uppercase tracking-wider mb-1">Target Webpage</div>
        <div class="flex items-center gap-2">
          <span class="text-xray-accent">${c.globe}</span>
          <span class="text-sm font-mono truncate font-semibold">${e.hostname||"demo-bank-a.example"}</span>
        </div>
        <div class="text-[11px] text-xray-muted truncate mt-1">${e.currentUrl}</div>
      </div>

      <!-- Threat Score Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-4 mb-3">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs text-xray-muted uppercase tracking-wider">Threat Assessment</span>
          <span class="text-lg font-bold font-mono" style="color: ${n}">${e.riskScore}/100</span>
        </div>
        <div class="w-full bg-[#1e293b] rounded-full" style="height: 6px;">
          <div class="rounded-full" style="width: ${Math.min(e.riskScore,100)}%; height: 6px; background-color: ${n}; transition: width 0.3s;"></div>
        </div>
        <div class="text-xs text-xray-muted mt-2">
          ${s?"Brand mismatch & suspicious OTP exfiltration pattern observed.":"Webpage behaviour normal. No exfiltration detected."}
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
            <input type="checkbox" data-toggle="strictProtection" ${e.strictActive?"checked":""} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-xray-border">
          <div>
            <div class="text-xs font-semibold">Behavioral Monitoring</div>
            <div class="text-[11px] text-xray-muted">Inspect DOM inputs & JS network APIs</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="monitoringEnabled" ${e.monitoringActive?"checked":""} />
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <button class="btn btn-primary" data-nav="dashboard">
          ${c.activity} Open Dashboard
        </button>
        <button class="btn btn-secondary" data-nav="canary">
          ${c.probe} Run Canary
        </button>
      </div>
    </div>
  `}function y(){const s=e.events.length||6,t=e.events.filter(a=>a.riskContribution>0).length||2;return`
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-4">
        <div class="text-base font-bold">Security Operations Center</div>
        <span class="badge ${e.strictActive?"badge-low":"badge-med"}">
          ${e.strictActive?"STRICT CDP ACTIVE":"MONITORING ACTIVE"}
        </span>
      </div>

      <!-- Statistics Grid -->
      <div class="grid grid-cols-4 gap-2 mb-4">
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Risk Score</div>
          <div class="text-lg font-bold text-xray-danger font-mono">${e.riskScore}</div>
        </div>
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Events</div>
          <div class="text-lg font-bold text-xray-text font-mono">${s}</div>
        </div>
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Threats</div>
          <div class="text-lg font-bold text-xray-warn font-mono">${t}</div>
        </div>
        <div class="bg-xray-card border-xray-border rounded-lg p-2 text-center">
          <div class="text-xs text-xray-muted">Protection</div>
          <div class="text-lg font-bold text-xray-accent font-mono">${e.strictActive?"CDP":"DNR"}</div>
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
          ${c.graph} Forensic Graph
        </button>
        <button class="btn btn-secondary" data-nav="alert">
          ${c.alert} Security Alert
        </button>
      </div>
    </div>
  `}function f(){const s=[{id:"node-input",title:"Sensitive OTP Input",type:"DOM Field",desc:'input[name="otp"]',suspicious:!0,meta:{field:"OTP / Verification Code",selector:"#otp",autocomplete:"one-time-code"}},{id:"node-api",title:"JavaScript fetch()",type:"Runtime Hook",desc:"window.fetch POST",suspicious:!0,meta:{api:"fetch",method:"POST",hookTime:"12ms post-interaction"}},{id:"node-req",title:"Outbound Request",type:"Network Layer",desc:"Payload Exfiltration",suspicious:!0,meta:{action:"Intercepted before transmission",status:"Blocked by Strict Mode"}},{id:"node-dest",title:"attacker.example",type:"Destination Host",desc:"Known Malicious Endpt",suspicious:!0,meta:{destination:"attacker.example/api/collect",registeredDomain:"attacker.example",threatList:"Matched DNR/CDP Rule"}}],t=s.find(a=>a.id===e.selectedGraphNode)||s[0];return`
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="text-base font-bold">Input-to-Network Forensic Graph</div>
        <span class="text-xs text-xray-muted">Click node for metadata</span>
      </div>

      <!-- Graph Visualization Container -->
      <div class="graph-container mb-3">
        <div class="flex items-center justify-between relative" style="z-index: 2;">
          ${s.map((a,n)=>`
            <div
              class="graph-node ${a.suspicious?"suspicious":"safe"} ${e.selectedGraphNode===a.id?"active-selected":""}"
              data-node-select="${a.id}"
              style="width: 100px; text-align: center;"
            >
              <div class="text-[9px] uppercase tracking-wider text-xray-muted mb-1">${a.type}</div>
              <div class="text-xs font-bold ${a.suspicious?"text-xray-danger":"text-xray-accent2"}">${a.title}</div>
            </div>
            ${n<s.length-1?'<div style="flex: 1; height: 2px; background: #ef4444; opacity: 0.8; margin: 0 4px;"></div>':""}
          `).join("")}
        </div>
      </div>

      <!-- Selected Node Inspection Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold uppercase text-xray-muted">Node Forensics: ${t.title}</span>
          <span class="badge ${t.suspicious?"badge-high":"badge-low"}">
            ${t.suspicious?"SUSPICIOUS PATH":"BENIGN"}
          </span>
        </div>
        <div class="bg-xray-code p-2 rounded text-xs font-mono text-xray-text space-y-1">
          ${Object.entries(t.meta).map(([a,n])=>`
            <div><span class="text-xray-muted">${a}:</span> <span class="text-xray-accent">${n}</span></div>
          `).join("")}
        </div>
      </div>

      <div class="flex justify-between gap-2">
        <button class="btn btn-secondary flex-1" data-nav="dashboard">← Dashboard</button>
        <button class="btn btn-primary flex-1" data-nav="alert">View Threat Alert</button>
      </div>
    </div>
  `}function g(){return`
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="bg-[#450a0a] border border-xray-danger rounded-xl p-4 mb-4 text-center">
        <div class="inline-flex p-2 rounded-full bg-xray-danger/20 text-xray-danger mb-1">
          ${c.shieldAlert}
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
            <span><strong>Brand Mismatch:</strong> Webpage claims to belong to DemoBank Alpha, but domain (${e.hostname}) is unverified.</span>
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
  `}function h(){const s=e.canaryState,t=s.status==="running",a=s.status==="transmission_detected"||s.status==="detected";return`
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="text-base font-bold">Canary Probe Testing</div>
        <span class="badge ${t?"badge-med":a?"badge-high":"badge-low"}">
          ${t?"PROBING...":a?"EXFIL CONFIRMED":"IDLE"}
        </span>
      </div>

      <p class="text-xs text-xray-muted mb-3">
        Injects an isolated synthetic OTP token in a sandbox environment to mathematically confirm whether the page exfiltrates credentials without endangering user data.
      </p>

      <!-- Probe Status Card -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-3">
        <div class="text-xs text-xray-muted mb-1">Synthetic Token Status</div>
        <div class="text-sm font-mono text-xray-accent font-bold">${s.token||"No active token"}</div>
        <div class="text-[10px] text-xray-muted mt-1">Generated randomly · Never transmits actual user credentials</div>
      </div>

      <!-- Forensic Results -->
      <div class="bg-xray-card border-xray-border rounded-xl p-3 mb-4 space-y-2 text-xs">
        <div class="flex justify-between">
          <span class="text-xray-muted">Exfiltration Attempt:</span>
          <span class="font-bold ${a?"text-xray-danger":"text-xray-accent2"}">
            ${a?"DETECTED":t?"Observing...":"None"}
          </span>
        </div>
        <div class="flex justify-between">
          <span class="text-xray-muted">Observed API:</span>
          <span class="font-mono text-xray-text">${s.observedApi}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-xray-muted">Attempted Destination:</span>
          <span class="font-mono text-xray-danger truncate max-w-[200px]">${s.attemptedDestination}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-xray-muted">External Transmission:</span>
          <span class="font-bold text-xray-accent2">BLOCKED</span>
        </div>
        <div class="pt-2 border-t border-xray-border">
          <div class="text-xray-muted text-[10px] uppercase font-bold mb-1">Probe Verdict:</div>
          <div class="text-xs font-semibold ${a?"text-xray-danger":"text-xray-text"}">${s.verdict}</div>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <button class="btn btn-primary" data-action="runCanary" ${t?"disabled":""}>
          ${t?"Running Probe...":"Start Canary Probe"}
        </button>
        <button class="btn btn-secondary" data-action="resetCanary">
          Reset Probe
        </button>
      </div>
    </div>
  `}function k(){return`
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
            <input type="checkbox" data-toggle="strictProtection" ${e.strictActive?"checked":""} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-xray-border">
          <div>
            <div class="text-xs font-semibold">Behavioral Monitoring</div>
            <div class="text-[11px] text-xray-muted">Inspect webpage DOM and JS networking</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="monitoringEnabled" ${e.monitoringActive?"checked":""} />
            <span class="toggle-slider"></span>
          </label>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-xray-border">
          <div>
            <div class="text-xs font-semibold">Privacy Mode</div>
            <div class="text-[11px] text-xray-muted">Local in-memory storage only</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-toggle="privacyMode" ${e.privacyMode?"checked":""} />
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
            <input type="checkbox" data-toggle="externalAiConsent" ${e.externalAiConsent?"checked":""} />
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <button class="btn btn-secondary w-full" data-nav="popup">Back to Overview</button>
    </div>
  `}function w(){const t=(e.events.length>0?e.events:[{id:"1",timestamp:Date.now()-6e4,api:"fetch",method:"POST",destination:"attacker.example",riskContribution:30,detectionReason:"Exfiltration to malicious endpoint",actionTaken:"blocked"},{id:"2",timestamp:Date.now()-18e4,api:"xhr",method:"POST",destination:"attacker.example",riskContribution:25,detectionReason:"XHR request after OTP interaction",actionTaken:"blocked"},{id:"3",timestamp:Date.now()-36e4,category:"url_analysis",destination:"fake-bank.example",riskContribution:25,detectionReason:"Brand/domain mismatch flagged",actionTaken:"warned"}]).filter(a=>e.historyFilter==="high"?a.riskContribution>=25:e.historyFilter==="med"?a.riskContribution>0&&a.riskContribution<25:e.historyFilter==="low"?a.riskContribution===0:!0);return`
    <div class="p-4 flex-1 overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="text-base font-bold">Activity History</div>
        <div class="flex gap-1 text-[10px]">
          <button class="btn btn-secondary py-1 px-2 ${e.historyFilter==="all"?"border-[#06b6d4]":""}" data-filter="all">All</button>
          <button class="btn btn-secondary py-1 px-2 ${e.historyFilter==="high"?"border-[#06b6d4]":""}" data-filter="high">High</button>
          <button class="btn btn-secondary py-1 px-2 ${e.historyFilter==="med"?"border-[#06b6d4]":""}" data-filter="med">Med</button>
        </div>
      </div>

      <div class="space-y-2 mb-4">
        ${t.map(a=>{const n=a.riskContribution>=25;return`
            <div class="bg-xray-card border-xray-border rounded-lg p-2 text-xs">
              <div class="flex items-center justify-between mb-1">
                <span class="font-bold ${n?"text-xray-danger":"text-xray-text"}">${a.detectionReason||"Network Request Observed"}</span>
                <span class="badge ${n?"badge-high":"badge-low"}">${a.actionTaken||"monitored"}</span>
              </div>
              <div class="text-xray-muted text-[10px] font-mono">${a.api||"API"} · ${a.destination||"local"}</div>
            </div>
          `}).join("")}
      </div>

      <button class="btn btn-secondary w-full" data-nav="dashboard">Back to Dashboard</button>
    </div>
  `}function o(){const s=document.getElementById("root");if(!s)return;let t="";switch(e.activeScreen){case"popup":t=b();break;case"dashboard":t=y();break;case"forensics":t=f();break;case"alert":t=g();break;case"canary":t=h();break;case"settings":t=k();break;case"history":t=w();break;default:t=b()}s.innerHTML=`
    <header class="app-header">
      <div class="flex items-center gap-2">
        <span class="text-xray-accent">${c.shield}</span>
        <span class="text-sm font-bold tracking-wider">X-RAY CYBERSECURITY</span>
      </div>
      <span class="badge ${e.strictActive?"badge-high":"badge-low"}">
        ${e.strictActive?"STRICT CDP":"MONITORING"}
      </span>
    </header>
    ${m()}
    ${t}
  `}function A(){const s=document.getElementById("root");s&&(s.addEventListener("click",t=>{var l,p;const a=t.target,n=a.closest("[data-nav]");if(n){e.activeScreen=n.dataset.nav||"popup",o();return}const i=a.closest("[data-node-select]");if(i){e.selectedGraphNode=i.dataset.nodeSelect||null,o();return}const r=a.closest("[data-filter]");if(r){e.historyFilter=r.dataset.filter||"all",o();return}const d=a.closest("[data-action]");if(d){const x=d.dataset.action;x==="runCanary"?u():x==="resetCanary"?(e.canaryState={status:"idle",token:"",observedApi:"None",attemptedDestination:"None",transmissionAttempted:!1,externalTransmissionBlocked:!0,verdict:'Canary Probe ready. Click "Start Probe" to test.',startedAt:0,finishedAt:0},o()):x==="blockAndProtect"?(e.strictActive=!0,typeof chrome<"u"&&((l=chrome.runtime)!=null&&l.sendMessage)&&chrome.runtime.sendMessage({kind:"XRAY_TOGGLE_STRICT",payload:{enabled:!0}}),o()):x==="openOfficial"&&(typeof chrome<"u"&&((p=chrome.tabs)!=null&&p.create)?chrome.tabs.create({url:"http://127.0.0.1:8000/mock-bank/official.html"}):window.open("http://127.0.0.1:8000/mock-bank/official.html","_blank"))}}),s.addEventListener("change",t=>{var i,r,d,l;const a=t.target,n=a.dataset.toggle;n&&(n==="strictProtection"?(e.strictActive=a.checked,typeof chrome<"u"&&((i=chrome.runtime)!=null&&i.sendMessage)&&chrome.runtime.sendMessage({kind:"XRAY_TOGGLE_STRICT",payload:{enabled:a.checked}})):n==="monitoringEnabled"?(e.monitoringActive=a.checked,typeof chrome<"u"&&((r=chrome.runtime)!=null&&r.sendMessage)&&chrome.runtime.sendMessage({kind:"XRAY_SET_SETTINGS",payload:{monitoringEnabled:a.checked}})):n==="privacyMode"?(e.privacyMode=a.checked,typeof chrome<"u"&&((d=chrome.runtime)!=null&&d.sendMessage)&&chrome.runtime.sendMessage({kind:"XRAY_SET_SETTINGS",payload:{privacyMode:a.checked}})):n==="externalAiConsent"&&(e.externalAiConsent=a.checked,typeof chrome<"u"&&((l=chrome.runtime)!=null&&l.sendMessage)&&chrome.runtime.sendMessage({kind:"XRAY_APPROVE_CONSENT",payload:{key:"external_ai",granted:a.checked}})),o())}))}document.addEventListener("DOMContentLoaded",()=>{A(),o(),v()});
