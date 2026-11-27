/**
 * X-Ray Content Script (ISOLATED world)
 *
 * Coordinates:
 * - DOM Analysis
 * - URL Analysis
 * - Runtime monitoring events from MAIN world
 * - Risk assessment
 * - Storage updates
 *
 * Runs in ISOLATED world - CANNOT access page's JavaScript directly.
 * Communicates with MAIN world via window.postMessage for network events.
 * All DOM analysis is performed here in isolated context for safety.
 */

import type {
  RuntimeMessage,
  ForensicsEvent,
  MonitoredRequest,
  UrlAnalysis,
  DomAnalysis,
  RiskAssessment,
} from './types';

// Import analyzer modules
import { analyzeDom, watchForSensitiveFields } from './modules/dom-analyzer';
import { analyzeUrl } from './modules/url-analyzer';
import { assessRisk } from './modules/risk-engine';
import { initDnrRules } from './modules/network-interceptor';
import type { SensitiveFieldInfo } from './types';

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------

/** Listen for MAIN-world network events */
chrome.runtime.onMessage.addListener(
  (message: RuntimeMessage, sender: chrome.runtime.MessageSender, sendResponse) => {
    switch (message.kind) {
      case 'XRAY_NETWORK_EVENT':
        handleNetworkEvent(message.payload);
        break;
      case 'XRAY_DOM_ANALYSIS':
        // DOM analysis is done here - this shouldn't normally be received
        break;
      case 'XRAY_GET_STATE':
        // Response handled by background
        break;
    }
  },
);

// Also listen for window.postMessage from MAIN world
// CRITICAL: MAIN-world messages must be validated
window.addEventListener('message', (event) => {
  // Only accept messages from same window
  if (event.source !== window) return;

  try {
    const message = event.data as any;

    // Validate message structure
    if (message?.kind !== 'XRAY_NETWORK_EVENT') return;
    if (message?.payload?.id === undefined) return;

    // Validate required fields
    const { id, api, method, url, destinationHost, timestamp, sourcePage } = message.payload;
    if (!id || !api || !destinationHost || !timestamp) return;

    // Construct safe MonitoredRequest object
    const safeRequest: MonitoredRequest = {
      id,
      api: api as any,
      method,
      url,
      destinationHost,
      timestamp,
      sourcePage,
      resourceType: message.payload.resourceType || '',
      correlatedWithSensitiveInput: message.payload.correlatedWithSensitiveInput || false,
    };

    handleNetworkEvent(safeRequest);
  } catch (e) {
    // Ignore malformed messages from page
    console.warn('[X-Ray] Ignored malformed MAIN-world message:', e);
  }
});

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let currentUrlAnalysis: UrlAnalysis | null = null;
let currentDomAnalysis: DomAnalysis | null = null;
let currentRiskAssessment: RiskAssessment | null = null;
let monitoredEvents: MonitoredRequest[] = [];
let recentSensitiveInteractions: Array<{
  fieldType: string;
  timestamp: number;
}> = [];

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

async function init(): Promise<void> {
  try {
    // 1. Analyze URL
    currentUrlAnalysis = await analyzeUrl(window.location.href);

    // 2. Analyze DOM
    currentDomAnalysis = analyzeDom();

    // 3. Monitor for sensitive fields being added dynamically
    watchForSensitiveFields((field: SensitiveFieldInfo) => {
      console.log('[X-Ray] New sensitive field detected:', field.type, field.selector);
      // Field info only - never the value
    });

    // 4. Initialize DNR rules
    await initDnrRules();

    // 5. Send initial analysis to background
    await sendInitialAnalysis();

    // 6. Update state
    await updateState();

  } catch (e) {
    console.error('[X-Ray] Content script init error:', e);
  }
}

async function sendInitialAnalysis(): Promise<void> {
  if (!currentUrlAnalysis || !currentDomAnalysis) return;

  // Calculate initial risk
  const assessment = assessRisk(currentUrlAnalysis, currentDomAnalysis, []);
  currentRiskAssessment = assessment;

  // Send to background
  try {
    await chrome.runtime.sendMessage({
      kind: 'XRAY_ANALYSIS_COMPLETE',
      payload: {
        urlAnalysis: currentUrlAnalysis,
        domAnalysis: currentDomAnalysis,
        assessment,
      },
    });
  } catch (e) {
    console.warn('[X-Ray] Could not send analysis to background:', e);
  }
}

async function updateState(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      kind: 'XRAY_GET_STATE',
      payload: {},
    });
  } catch (e) {
    // Background may not be ready yet
  }
}

// ---------------------------------------------------------------------------
// Network Event Handling
// ---------------------------------------------------------------------------

function handleNetworkEvent(request: MonitoredRequest): void {
  // Validate event
  if (!isValidEvent(request)) {
    console.warn('[X-Ray] Invalid network event:', request);
    return;
  }

  // Track event
  monitoredEvents.push(request);
  if (monitoredEvents.length > 500) {
    // Keep buffer size manageable
    monitoredEvents = monitoredEvents.slice(-500);
  }

  // Check correlation with sensitive field interaction
  if (request.correlatedWithSensitiveInput) {
    console.log('[X-Ray] Correlated sensitive field interaction detected:', request.api, request.destinationHost);
  }

  // Re-assess risk with new events
  if (currentUrlAnalysis && currentDomAnalysis) {
    const assessment = assessRisk(currentUrlAnalysis, currentDomAnalysis, monitoredEvents);
    currentRiskAssessment = assessment;

    // Send update to background
    sendRiskUpdate(assessment);
  }
}

function isValidEvent(event: MonitoredRequest): boolean {
  if (!event || typeof event !== 'object') return false;
  if (typeof event.id !== 'string') return false;
  if (typeof event.api !== 'string') return false;
  if (typeof event.destinationHost !== 'string') return false;
  if (typeof event.timestamp !== 'number') return false;
  if (typeof event.sourcePage !== 'string') return false;
  return true;
}

async function sendRiskUpdate(assessment: RiskAssessment): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      kind: 'XRAY_RISK_UPDATE',
      payload: {
        assessment,
        monitoredEvents: monitoredEvents.slice(-50), // Send recent events
      },
    });
  } catch (e) {
    console.warn('[X-Ray] Could not send risk update:', e);
  }
}

// ---------------------------------------------------------------------------
// Message from Background: State Updates
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener(
  (message: any, sender, sendResponse) => {
    if (message?.kind === 'XRAY_APPLY_SETTINGS') {
      // Apply new settings (e.g., scoring weights)
      // Re-run assessment with new rules
      if (currentUrlAnalysis && currentDomAnalysis) {
        const assessment = assessRisk(
          currentUrlAnalysis,
          currentDomAnalysis,
          monitoredEvents,
          null,
          message.payload?.scoringRules,
        );
        currentRiskAssessment = assessment;
        sendRiskUpdate(assessment);
      }
    }
    return true; // Keep channel open for async response
  },
);

// ---------------------------------------------------------------------------
// Auto-initialize when DOM is ready
// ---------------------------------------------------------------------------

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Clean up on unload
window.addEventListener('beforeunload', () => {
  // No action needed - browser will clean up
});