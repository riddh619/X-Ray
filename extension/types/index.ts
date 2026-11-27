/**
 * X-Ray Shared Type Definitions
 * All components communicate through these consistent interfaces.
 */

// ---------------------------------------------------------------------------
// Event & Evidence Types
// ---------------------------------------------------------------------------

export type EventCategory =
  | 'network_request'
  | 'form_submission'
  | 'dom_analysis'
  | 'url_analysis'
  | 'canary_probe'
  | 'system';

export type NetworkApi = 'fetch' | 'xhr' | 'sendBeacon' | 'websocket' | 'form';

export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export type ActionTaken =
  | 'none'
  | 'blocked'
  | 'monitored'
  | 'warned'
  | 'allowed';

export interface ForensicsEvent {
  id: string;
  timestamp: number;
  sourcePage: string; // e.g. "fake-bank.example"
  tabId?: number;
  category: EventCategory;
  api?: NetworkApi;
  method?: string;
  destination?: string;
  resourceType?: string;
  riskContribution: number;
  detectionReason: string;
  actionTaken: ActionTaken;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// URL / Brand Analysis
// ---------------------------------------------------------------------------

export interface UrlAnalysis {
  rawUrl: string;
  hostname: string;
  registeredDomain: string; // e.g. "example.com"
  subdomain: string;
  protocol: string;
  isHttps: boolean;
  isIpAddress: boolean;
  hasPunycode: boolean;
  homoglyphRisk: boolean;
  homoglyphDetail?: string;
  mixedScriptRisk: boolean;
  suspiciousPatterns: string[];
  brandMatch: BrandMatch | null;
  riskContribution: number;
  reasons: string[];
}

export interface BrandMatch {
  brandId: string;
  brandName: string;
  officialDomain: string;
  claimedBrand: boolean;
  domainMatches: boolean;
  mismatch: boolean;
  confidence: number; // 0..1
  reason: string;
}

export interface BrandRegistryEntry {
  brandId: string;
  brandName: string;
  officialDomain: string;
  aliases: string[];
  keywords: string[]; // title / page-text keywords
  logoColor?: string;
}

// ---------------------------------------------------------------------------
// DOM Analysis
// ---------------------------------------------------------------------------

export interface SensitiveFieldInfo {
  fieldId: string;
  type: 'password' | 'otp' | 'email' | 'username' | 'other';
  selector: string;
  inputType: string;
  autocomplete?: string;
  name?: string;
  id?: string;
  ariaLabel?: string;
  placeholder?: string;
}

export interface AuthFormInfo {
  formId: string;
  action: string;
  isExternalAction: boolean;
  method: string;
  hasPassword: boolean;
  hasOtp: boolean;
  hasEmail: boolean;
}

export interface HiddenIframeInfo {
  src: string;
  reasons: string[];
}

export interface DomAnalysis {
  url: string;
  title: string;
  passwordFields: SensitiveFieldInfo[];
  otpFields: SensitiveFieldInfo[];
  emailFields: SensitiveFieldInfo[];
  usernameFields: SensitiveFieldInfo[];
  authForms: AuthFormInfo[];
  hiddenIframes: HiddenIframeInfo[];
  suspiciousEmbedded: string[];
  pageBrandKeywords: string[];
  riskContribution: number;
  reasons: string[];
}

// ---------------------------------------------------------------------------
// Runtime Monitoring Events (from MAIN world instrumentation)
// ---------------------------------------------------------------------------

export interface MonitoredRequest {
  id: string;
  api: NetworkApi;
  method: string;
  url: string;
  destinationHost: string;
  timestamp: number;
  sourcePage: string;
  resourceType?: string;
  /** True if this was triggered shortly after a sensitive field interaction */
  correlatedWithSensitiveInput: boolean;
  /** The sensitive field types that were recently interacted with, if any */
  sensitiveContext?: Array<'password' | 'otp' | 'email' | 'username'>;
  /** Whether the request body contained the canary token (never the actual value) */
  containsCanary?: boolean;
  /** Size indicator only - never actual content */
  bodySizeHint?: number;
}

// ---------------------------------------------------------------------------
// Risk Engine
// ---------------------------------------------------------------------------

export interface RiskContribution {
  ruleId: string;
  label: string;
  points: number;
  reason: string;
  evidenceRef?: string;
}

export interface RiskAssessment {
  score: number; // 0..100
  level: ThreatLevel;
  contributions: RiskContribution[];
  verdict: string;
  explanation: string;
}

export interface ScoringRule {
  id: string;
  label: string;
  points: number;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Canary Probe
// ---------------------------------------------------------------------------

export type CanaryStatus =
  | 'idle'
  | 'running'
  | 'transmission_detected'
  | 'no_transmission'
  | 'error';

export interface CanaryProbeResult {
  status: CanaryStatus;
  tokenStatus: 'generated' | 'none';
  observedApi?: NetworkApi;
  attemptedDestination?: string;
  transmissionAttempted: boolean;
  externalTransmissionBlocked: boolean;
  verdict: string;
  startedAt: number;
  finishedAt?: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// Protection / Settings
// ---------------------------------------------------------------------------

export interface ProtectionSettings {
  basicProtection: boolean;
  strictProtection: boolean;
  privacyMode: boolean;
  externalAiConsent: boolean;
  monitoringEnabled: boolean;
  scoringRules: ScoringRule[];
}

export interface ConsentRecord {
  key:
    | 'extension_permissions'
    | 'canary_probe'
    | 'external_ai'
    | 'safe_navigation'
    | 'cybercrime_report';
  granted: boolean;
  grantedAt?: number;
}

// ---------------------------------------------------------------------------
// Tab / Extension State
// ---------------------------------------------------------------------------

export interface TabState {
  tabId: number;
  url: string;
  hostname: string;
  title: string;
  riskScore: number;
  threatLevel: ThreatLevel;
  monitoringActive: boolean;
  strictActive: boolean;
  lastAnalysis?: number;
  urlAnalysis?: UrlAnalysis;
  domAnalysis?: DomAnalysis;
  events: ForensicsEvent[];
}

// ---------------------------------------------------------------------------
// Messaging protocol between MAIN <-> content <-> background <-> UI
// ---------------------------------------------------------------------------

export type RuntimeMessage =
  | { kind: 'XRAY_NETWORK_EVENT'; payload: MonitoredRequest }
  | { kind: 'XRAY_SENSITIVE_INTERACTION'; payload: { fieldType: string; timestamp: number } }
  | { kind: 'XRAY_DOM_ANALYSIS'; payload: DomAnalysis }
  | { kind: 'XRAY_URL_ANALYSIS'; payload: UrlAnalysis }
  | { kind: 'XRAY_GET_STATE'; tabId?: number }
  | { kind: 'XRAY_START_CANARY'; payload: { tabId: number } }
  | { kind: 'XRAY_SET_SETTINGS'; payload: Partial<ProtectionSettings> }
  | { kind: 'XRAY_TOGGLE_STRICT'; payload: { enabled: boolean } }
  | { kind: 'XRAY_APPROVE_CONSENT'; payload: { key: ConsentRecord['key']; granted: boolean } }
  | { kind: 'XRAY_NAVIGATE_SAFE'; payload: { url: string } };

// ---------------------------------------------------------------------------
// Graph model
// ---------------------------------------------------------------------------

export type GraphNodeKind = 'sensitive_input' | 'js_api' | 'request' | 'destination';

export interface GraphNodeData {
  label: string;
  kind: GraphNodeKind;
  suspicious: boolean;
  metadata: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  type: 'forensic';
  data: GraphNodeData;
  position: { x: number; y: number };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  suspicious: boolean;
  label?: string;
}
