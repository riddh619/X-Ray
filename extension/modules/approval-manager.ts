/**
 * Human-in-the-Loop Approval Manager
 *
 * Separate consent categories with deterministic workflow.
 * Never asks user to approve every network request.
 * If protection policy + strong malicious condition -> block immediately.
 * User controls: Block & protect, View forensic evidence,
 * Open verified official website, Review detection explanation.
 */

import type {
  ConsentRecord,
  ConsentKey,
  ProtectionSettings,
  ThreatLevel,
  ForensicsEvent,
} from '../types';

// ---------------------------------------------------------------------------
// Consent Category Definitions
// ---------------------------------------------------------------------------

export const ConsentCategories = {
  EXTENSION_PERMISSIONS: 'extension_permissions',
  CANARY_PROBE: 'canary_probe',
  EXTERNAL_AI: 'external_ai',
  SAFE_NAVIGATION: 'safe_navigation',
  CYBERCRIME_REPORT: 'cybercrime_report',
} as const;

export type ConsentCategory =
  | typeof ConsentCategories.EXTENSION_PERMISSIONS
  | typeof ConsentCategories.CANARY_PROBE
  | typeof ConsentCategories.EXTERNAL_AI
  | typeof ConsentCategories.SAFE_NAVIGATION
  | typeof ConsentCategories.CYBERCRIME_REPORT;

// ---------------------------------------------------------------------------
// Default Consent State
// ---------------------------------------------------------------------------

async function loadConsentState(): Promise<Map<ConsentCategory, boolean>> {
  try {
    const result = await chrome.storage.local.get('xray_consent');
    const raw = result.xray_consent || {};
    const consentMap = new Map<ConsentCategory, boolean>();
    for (const [key, granted] of Object.entries(raw) as [ConsentCategory, boolean][]) {
      consentMap.set(key, granted);
    }
    // Ensure all categories exist
    for (const cat of Object.values(ConsentCategories) as ConsentCategory[]) {
      if (!consentMap.has(cat)) {
        consentMap.set(cat, false);
      }
    }
    return consentMap;
  } catch {
    // Return defaults
    const defaults = new Map<ConsentCategory, boolean>();
    for (const cat of Object.values(ConsentCategories) as ConsentCategory[]) {
      defaults.set(cat, false);
    }
    return defaults;
  }
}

async function saveConsentState(consentMap: Map<ConsentCategory, boolean>): Promise<void> {
  try {
    const raw: Record<ConsentCategory, boolean> = {};
    for (const [key, value] of consentMap) {
      raw[key] = value;
    }
    await chrome.storage.local.set({ xray_consent: raw });
  } catch (e) {
    console.warn('[X-Ray] Could not save consent state:', e);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

let consentCache: Map<ConsentCategory, boolean> | null = null;

export async function getConsent(category: ConsentCategory): Promise<boolean> {
  // Return cached value if available, otherwise load
  if (consentCache) {
    return consentCache.get(category) ?? false;
  }
  const state = await loadConsentState();
  consentCache = state;
  return state.get(category) ?? false;
}

export async function setConsent(
  category: ConsentCategory,
  granted: boolean,
  reason?: string,
): Promise<void> {
  const state = await loadConsentState();
  state.set(category, granted);
  await saveConsentState(state);
  consentCache = state;

  console.log(`[X-Ray] Consent ${category}: ${granted}${
    reason ? ` - ${reason}` : ''
  }`);
}

/**
 * Check if user has granted extension permissions.
 * This is a prerequisite for monitoring to start.
 */
export async function hasExtensionPermissions(): Promise<boolean> {
  return getConsent(ConsentCategories.EXTENSION_PERMISSIONS);
}

/**
 * Check if Canary Probe consent has been given.
 */
export async function hasCanaryConsent(): Promise<boolean> {
  return getConsent(ConsentCategories.CANARY_PROBE);
}

/**
 * Check if external AI processing consent has been given.
 */
export async function hasExternalAiConsent(): Promise<boolean> {
  return getConsent(ConsentCategories.EXTERNAL_AI);
}

/**
 * Check if safe navigation consent has been given.
 */
export async function hasSafeNavigationConsent(): Promise<boolean> {
  return getConsent(ConsentCategories.SAFE_NAVIGATION);
}

/**
 * Check if cybercrime report consent has been given.
 */
export async function hasCybercrimeReportConsent(): Promise<boolean> {
  return getConsent(ConsentCategories.CYBERCRIME_REPORT);
}

/**
 * Record a security action approval.
 * Used for Human-in-the-Loop decisions on detected threats.
 */
export interface SecurityActionApproval {
  eventId: string;
  threatLevel: ThreatLevel;
  userDecision: 'block' | 'allow' | 'view_evidence' | 'navigate_official';
  timestamp: number;
  reason?: string;
}

export async function recordSecurityAction(
  approval: SecurityActionApproval,
): Promise<void> {
  try {
    const result = await chrome.storage.local.get('xray_security_actions');
    const existing = result.xray_security_actions || [];
    existing.push(approval);
    await chrome.storage.local.set({ xray_security_actions: existing.slice(-100) });
  } catch (e) {
    console.warn('[X-Ray] Could not record security action:', e);
  }
}

/**
 * Get pending actions awaiting user approval.
 */
export async function getPendingApprovals(): Promise<SecurityActionApproval[]> {
  try {
    const result = await chrome.storage.local.get('xray_pending_approvals');
    return result.xray_pending_approvals || [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Protection Decision Logic
// --------------------------------------------------------------------------------
//
// IMPORTANT: Human-in-the-Loop overrides
//
// If user has NOT enabled a protection policy and a request matches a condition,
// the request should be monitored and explained, NOT blocked automatically.
//
// If user HAS enabled a protection policy and a request matches a sufficiently
// strong malicious condition, block it immediately without further consent.
//
// The distinction is explicit in the spec:
// - Monitoring active -> explain, user decides
// - Strict interception active -> block immediately on strong match
// - Never casual "allow OTP theft" button
// - Provide: Block and protect, View forensic evidence, Open verified official website, Review detection explanation
// --------------------------------------------------------------------------------

/**
 * Evaluate whether a detected threat requires user approval or can be auto-blocked.
 * Returns the recommended action and whether consent is needed.
 */
export interface ThreatEvaluation {
  action: 'blockImmediately' | 'requestConsent' | 'monitorOnly';
  consentNeeded: ConsentCategory | null;
  message: string;
}

export async function evaluateThreat(
  assessment: { score: number; level: ThreatLevel },
  canaryDetected: boolean,
): Promise<ThreatEvaluation> {
  // If Canary exfiltration confirmed -> HIGH risk always requires user action
  if (canaryDetected) {
    return {
      action: 'requestConsent',
      consentNeeded: ConsentCategories.CANARY_PROBE,
      message: 'Canary Probe confirmed exfiltration attempt. What would you like to do?',
    };
  }

  // HIGH risk with protection enabled -> block immediately
  if (assessment.level === 'HIGH') {
    const hasProtection = await hasExtensionPermissions();
    if (hasProtection) {
      return {
        action: 'blockImmediately',
        consentNeeded: null,
        message: `HIGH RISK threat detected (score: ${assessment.score}/100). Automatically blocked to protect your data.`,
      };
    }
    // No protection enabled -> request consent to monitor/block
    return {
      action: 'requestConsent',
      consentNeeded: ConsentCategories.EXTENSION_PERMISSIONS,
      message: `HIGH RISK threat detected (score: ${assessment.score}/100). Enable protection to block?`,
    };
  }

  // MEDIUM risk -> monitor and explain
  if (assessment.level === 'MEDIUM') {
    return {
      action: 'monitorOnly',
      consentNeeded: null,
      message: `MEDIUM RISK indicators detected (score: ${assessment.score}/100). Monitoring active. Review evidence below.`,
    };
  }

  // LOW risk -> monitoring only
  return {
    action: 'monitorOnly',
    consentNeeded: null,
    message: `LOW RISK - No significant indicators. Continuing monitoring.`,
  };
}

// ---------------------------------------------------------------------------
// Forensic Event for UI Display
// ---------------------------------------------------------------------------

export interface ForensicDisplayEvent {
  id: string;
  timestamp: number;
  threatLevel: ThreatLevel;
  riskScore: number;
  title: string;
  summary: string;
  actions: ForensicAction[];
}

export interface ForensicAction {
  label: string;
  kind: 'primary' | 'secondary';
  handler: () => Promise<void>;
}

/**
 * Generate forensic display data for a detected threat.
 */
export async function generateForensicDisplay(
  assessment: RiskAssessment,
  urlAnalysis: UrlAnalysis | null,
  domAnalysis: DomAnalysis | null,
  canaryDetected: boolean,
): Promise<ForensicDisplayEvent> {
  const { score, level } = assessment;
  const consentGiven = await hasExtensionPermissions();

  // Determine primary action
  const evaluation = await evaluateThreat(assessment, canaryDetected);

  const actions: ForensicAction[] = [];

  // Always provide "View forensic evidence" as an option
  actions.push({
    label: 'View forensic evidence',
    kind: 'primary',
    handler: async () => {
      // Navigate to dashboard with forensic details
      // This would be handled by the UI
      chrome.runtime.sendMessage({
        kind: 'XRAY_SHOW_FORENSIC',
        assessment,
        urlAnalysis,
        domAnalysis,
        canaryDetected,
      });
    },
  });

  if (evaluation.action === 'blockImmediately') {
    actions.push({
      label: 'Learn more about this threat',
      kind: 'secondary',
      handler: async () => {
        // Show explanation
        chrome.runtime.sendMessage({
          kind: 'XRAY_SHOW_EXPLANATION',
          assessment,
          urlAnalysis,
          domAnalysis,
          canaryDetected,
        });
      },
    });
  } else if (evaluation.action === 'requestConsent') {
    // Provide context-specific actions based on consent category
    if (evaluation.consentNeeded === ConsentCategories.CANARY_PROBE) {
      actions.push({
        label: 'Continue monitoring (Do not block)',
        kind: 'secondary',
        handler: async () => {
          await setConsent(ConsentCategories.CANARY_PROBE, true, 'user_decided_to_monitor');
        },
      });
      actions.push({
        label: 'Block and protect',
        kind: 'primary',
        handler: async () => {
          await setConsent(ConsentCategories.CANARY_PROBE, false, 'user_decided_to_block');
          // In a full implementation, this would also trigger DNR blocking
        },
      });
    } else if (evaluation.consentNeeded === ConsentCategories.EXTENSION_PERMISSIONS) {
      actions.push({
        label: 'Enable X-Ray Protection',
        kind: 'primary',
        handler: async () => {
          await setConsent(ConsentCategories.EXTENSION_PERMISSIONS, true);
        },
      });
    }
  }

  return {
    id: `evt_${Date.now()}`,
    timestamp: Date.now(),
    threatLevel: level,
    riskScore: score,
    title: evaluation.message,
    summary: assessment.explanation || 'No explanation available',
    actions,
  };
}

