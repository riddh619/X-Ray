/**
 * Network Interception & Protection
 *
 * Two mechanisms:
 * 1. Declarative Net Request (DNR) - for known malicious domains
 * 2. Chrome Debugger API (CDP Fetch domain) - Strict Protection Mode
 *
 * Strict Mode requires explicit user consent and debugger attachment.
 * Gracefully falls back to monitoring-only if debugger unavailable.
 */

import type { ActionTaken, ProtectionSettings, NetworkApi, ThreatLevel } from '../types';

// ---------------------------------------------------------------------------
// DNR Rules for known malicious domains
// ---------------------------------------------------------------------------

const MALICIOUS_DOMAINS = [
  'attacker.example',
  'collector.example',
  'steal.example',
  'exfiltrate.example',
  'malicious.example',
];

/**
 * Build DNR rules from malicious domains list.
 */
export function buildDnrRules(): chrome.declarativeNetRequest.Rule[] {
  return MALICIOUS_DOMAINS.map((domain, index) => ({
    id: index + 1,
    priority: 1000,
    action: { type: 'block' },
    condition: {
      urlFilter: `*://*.${domain}/*`,
      resourceTypes: ['xmlhttprequest', 'fetch', 'beacon', 'other'],
    },
  }));
}

/**
 * Initialize DNR rules.
 */
export async function initDnrRules(): Promise<void> {
  try {
    const rules = buildDnrRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rules.map(r => r.id),
      addRules: rules,
    });
  } catch (e) {
    console.warn('[X-Ray] DNR initialization failed:', e);
  }
}

/**
 * Check if a URL matches known malicious DNR rules.
 */
export function isBlockedByDnr(url: string): boolean {
  try {
    const parsed = new URL(url);
    return MALICIOUS_DOMAINS.some(d => parsed.hostname.includes(d));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Chrome Debugger API - Strict Protection Mode
// ---------------------------------------------------------------------------

interface DebuggerSession {
  tabId: number;
  attached: boolean;
  targetId?: chrome.debugger.Debuggee;
}

let activeDebuggerSession: DebuggerSession | null = null;

/**
 * Attach debugger to a tab and enable Fetch domain interception.
 */
export async function attachDebugger(tabId: number): Promise<boolean> {
  try {
    // Check if we already have a session
    if (activeDebuggerSession?.attached && activeDebuggerSession.tabId === tabId) {
      return true;
    }

    // Detach any existing session first
    if (activeDebuggerSession?.attached) {
      await detachDebugger();
    }

    // Check debugger permission
    const hasPermission = await new Promise<boolean>(resolve => {
      chrome.permissions.contains({
        permissions: ['debugger'],
      }, resolve);
    });

    if (!hasPermission) {
      console.warn('[X-Ray] Debugger permission not granted');
      return false;
    }

    // Attach to tab
    const target = { tabId };
    await new Promise<void>((resolve, reject) => {
      chrome.debugger.attach(target, '1.3', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Enable Fetch domain
    await new Promise<void>((resolve, reject) => {
      chrome.debugger.sendCommand(target, 'Fetch.enable', {
        patterns: [{ urlPattern: '*', requestStage: 'Request' }],
      }, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Set up event listener for requestPaused
    chrome.debugger.onEvent.addListener(onDebuggerEvent);

    activeDebuggerSession = {
      tabId,
      attached: true,
      targetId: target,
    };

    console.log('[X-Ray] Strict Protection Mode: Debugger attached to tab', tabId);
    return true;
  } catch (e) {
    console.error('[X-Ray] Debugger attachment failed:', e);
    activeDebuggerSession = null;
    return false;
  }
}

function onDebuggerEvent(
  source: chrome.debugger.Debuggee,
  method: string,
  params?: any,
): void {
  if (method === 'Fetch.requestPaused') {
    handleRequestPaused(source.tabId!, params);
  }
}

async function handleRequestPaused(
  tabId: number,
  params: { requestId: string; request: any; frameId: number; resourceType: string },
): Promise<void> {
  try {
    const { requestId, request, frameId, resourceType } = params;

    // Get current tab's risk state from storage
    const settings = await getProtectionSettings();
    if (!settings?.strictProtection) {
      // Strict mode disabled - allow request
      await continueRequest(requestId, request);
      return;
    }

    // Analyze request for malicious intent
    const decision = await analyzeAndDecide(request, tabId, resourceType);

    switch (decision.action) {
      case 'block':
        await failRequest(requestId);
        break;
      case 'warn':
        // For warnings, we still continue but log
        await continueRequest(requestId, request);
        break;
      default:
        await continueRequest(requestId, request);
    }
  } catch (e) {
    console.error('[X-Ray] Error handling requestPaused:', e);
    // On error, fail-safe: continue the request
    try {
      await chrome.debugger.sendCommand(
        { tabId },
        'Fetch.continueRequest',
        { requestId: params.requestId }
      );
    } catch {}
  }
}

interface InterceptionDecision {
  action: 'allow' | 'block' | 'warn';
  reason: string;
}

/**
 * Analyze a request and decide whether to block/warn/allow.
 * Returns decision based on current risk assessment and request metadata.
 */
async function analyzeAndDecide(
  request: any,
  tabId: number,
  resourceType: string,
): Promise<InterceptionDecision> {
  const url = request.url;

  // 1. Check known malicious domains
  if (MALICIOUS_DOMAINS.some(d => url.includes(d))) {
    return { action: 'block', reason: 'Known malicious domain' };
  }

  // 2. Check for suspicious patterns in URL
  if (isSuspiciousUrl(url)) {
    return { action: 'block', reason: 'Suspicious URL pattern (phishing-like)' };
  }

  // 3. Check if destination is a legitimate third-party service
  if (isLegitimateThirdParty(url)) {
    return { action: 'allow', reason: 'Legitimate third-party service' };
  }

  // 4. Check for cross-origin after sensitive interaction
  // This would need correlation data from the background service worker
  // For now, default to monitoring-only for unmatched requests
  return { action: 'allow', reason: 'No malicious pattern matched' };
}

function isSuspiciousUrl(url: string): boolean {
  const suspiciousPatterns = [
    'attacker',
    'collector',
    'steal',
    'exfiltrate',
    'malicious',
    'phish',
    'exfil',
    'data-grab',
    'grabber',
    'capture',
  ];
  const lower = url.toLowerCase();
  return suspiciousPatterns.some(p => lower.includes(p));
}

function isLegitimateThirdParty(url: string): boolean {
  const legitimateDomains = [
    'google-analytics.com',
    'googletagmanager.com',
    'facebook.net',
    'connect.facebook.net',
    'stripe.com',
    'js.stripe.com',
    'paypal.com',
    'recaptcha.net',
    'gstatic.com',
    'cloudflare.com',
  ];
  return legitimateDomains.some(d => url.includes(d));
}

async function continueRequest(
  requestId: string,
  request: any,
): Promise<void> {
  try {
    await chrome.debugger.sendCommand(
      { tabId: activeDebuggerSession?.tabId },
      'Fetch.continueRequest',
      { requestId }
    );
  } catch (e) {
    console.warn('[X-Ray] ContinueRequest failed:', e);
  }
}

async function failRequest(requestId: string): Promise<void> {
  try {
    await chrome.debugger.sendCommand(
      { tabId: activeDebuggerSession?.tabId },
      'Fetch.failRequest',
      { requestId, errorReason: 'BlockedByClient' }
    );
  } catch (e) {
    console.warn('[X-Ray] FailRequest failed:', e);
  }
}

/**
 * Detach debugger from current tab.
 */
export async function detachDebugger(): Promise<void> {
  if (!activeDebuggerSession?.attached) return;

  try {
    chrome.debugger.onEvent.removeListener(onDebuggerEvent);
    await chrome.debugger.detach({ tabId: activeDebuggerSession.tabId });
  } catch (e) {
    console.warn('[X-Ray] Debugger detach error:', e);
  } finally {
    activeDebuggerSession = null;
  }
}

/**
 * Check if Strict Protection Mode is currently active.
 */
export function isStrictModeActive(): boolean {
  return activeDebuggerSession?.attached === true;
}

/**
 * Get current debugger attachment info.
 */
export function getDebuggerStatus(): {
  active: boolean;
  tabId?: number;
} {
  return {
    active: activeDebuggerSession?.attached || false,
    tabId: activeDebuggerSession?.tabId,
  };
}

// ---------------------------------------------------------------------------
// Settings Management
// ---------------------------------------------------------------------------

async function getProtectionSettings(): Promise<ProtectionSettings | null> {
  try {
    const result = await chrome.storage.local.get('xray_settings');
    return result.xray_settings || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API for Background Service Worker
// ---------------------------------------------------------------------------

export interface ProtectionAction {
  action: ActionTaken;
  reason: string;
  blocked: boolean;
}

export async function evaluateRequest(
  url: string,
  method: string,
  api: NetworkApi,
  tabId: number,
): Promise<ProtectionAction> {
  // First check DNR (always active)
  if (isBlockedByDnr(url)) {
    return { action: 'blocked', reason: 'Blocked by DNR: known malicious domain', blocked: true };
  }

  // If strict mode active, CDP will handle interception
  // We just record the decision here
  if (isStrictModeActive()) {
    // Request will be intercepted by debugger
    return { action: 'monitored', reason: 'Strict mode: request intercepted by CDP', blocked: false };
  }

  // Basic protection: monitor only
  return { action: 'monitored', reason: 'Basic protection: monitoring only', blocked: false };
}