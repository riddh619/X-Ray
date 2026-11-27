/**
 * Risk Engine - Deterministic risk scoring for webpages.
 *
 * Scores based on domain reputation, homoglyph detection, brand mismatch,
 * sensitive inputs, suspicious network requests, iframes, Canary results.
 *
 * Maximum score: 100
 * Classification: 0-29 LOW, 30-59 MEDIUM, 60-100 HIGH
 *
 * Never: OTP field alone cannot cause HIGH verdict.
 * Never: double-count correlated evidence.
 */

import type {
  UrlAnalysis,
  DomAnalysis,
  MonitoredRequest,
  RiskAssessment,
  RiskContribution,
  ThreatLevel,
} from '../types';

// ---------------------------------------------------------------------------
// Default scoring weights (configurable)
// ---------------------------------------------------------------------------

const DEFAULT_WEIGHTS: Record<string, number> = {
  knownMaliciousDomain: 40,
  homoglyphDetection: 25,
  brandDomainMismatch: 25,
  otpFieldDetected: 5,
  sensitiveOutboundAfterOtp: 30,
  hiddenSuspiciousIframe: 10,
  canaryExfiltrationAttempt: 50,
  mixedScriptDomain: 15,
  suspiciousUrlPattern: 5,
  insecureHttp: 5,
  externalFormAction: 10,
  externalSuspiciousScript: 5,
};

export type ScoringRule = {
  id: string;
  label: string;
  points: number;
  enabled: boolean;
};

// ---------------------------------------------------------------------------
// Main scoring function
// ---------------------------------------------------------------------------

export function assessRisk(
  urlAnalysis: UrlAnalysis | null,
  domAnalysis: DomAnalysis | null,
  networkEvents: MonitoredRequest[],
  canaryResult: { transmissionDetected: boolean } | null,
  scoringRules?: Record<string, ScoringRule>,
): RiskAssessment {
  const weights = scoringRules || DEFAULT_WEIGHTS;
  const contributions: RiskContribution[] = [];
  let score = 0;

  const level = scoreToLevel(score);

  // --- 1. Known malicious domain ---
  if (urlAnalysis?.hostname &&
      isKnownMaliciousDomain(urlAnalysis.hostname)) {
    const w = weights.knownMaliciousDomain?.points ?? DEFAULT_WEIGHTS.knownMaliciousDomain;
    contributions.push({
      ruleId: 'knownMaliciousDomain',
      label: 'Known malicious domain',
      points: w,
      reason: `Domain "${urlAnalysis.hostname}" appears in local known-malicious registry`,
    });
    score += w;
  }

  // --- 2. Homoglyph detection ---
  if (urlAnalysis?.homoglyphRisk && urlAnalysis.homoglyphDetail) {
    const w = weights.homoglyphDetection?.points ?? DEFAULT_WEIGHTS.homoglyphDetection;
    contributions.push({
      ruleId: 'homoglyphDetection',
      label: 'Homoglyph / confusable character',
      points: w,
      reason: urlAnalysis.homoglyphDetail,
    });
    score += w;
  }

  // --- 3. Mixed script (only add if not already homoglyph flagged) ---
  if (urlAnalysis?.mixedScriptRisk && !urlAnalysis.homoglyphRisk) {
    const w = weights.mixedScriptDomain?.points ?? DEFAULT_WEIGHTS.mixedScriptDomain;
    contributions.push({
      ruleId: 'mixedScriptDomain',
      label: 'Mixed-script domain',
      points: w,
      reason: `Domain mixes multiple Unicode scripts`,
    });
    score += w;
  }

  // --- 4. Brand/domain mismatch ---
  if (urlAnalysis?.brandMatch?.mismatch && urlAnalysis.brandMatch.claimedBrand) {
    const w = weights.brandDomainMismatch?.points ?? DEFAULT_WEIGHTS.brandDomainMismatch;
    contributions.push({
      ruleId: 'brandDomainMismatch',
      label: 'Brand/domain mismatch',
      points: w,
      reason: urlAnalysis.brandMatch.reason,
    });
    score += w;
  }

  // --- 5. OTP field (low points alone - cannot cause HIGH alone) ---
  if (domAnalysis?.otpFields.length > 0) {
    const w = weights.otpFieldDetected?.points ?? DEFAULT_WEIGHTS.otpFieldDetected;
    contributions.push({
      ruleId: 'otpFieldDetected',
      label: 'OTP input field',
      points: w,
      reason: `${domAnalysis.otpFields.length} OTP field(s) detected on page`,
    });
    score += w;
  }

  // --- 6. Suspicious outbound request after OTP interaction ---
  const sensitiveCorrelatedEvents = networkEvents.filter(e =>
    e.correlatedWithSensitiveInput &&
    e.api !== undefined &&
    e.destinationHost &&
    e.destinationHost !== (urlAnalysis?.hostname || '') &&
    isDestinationSuspicious(e.destinationHost)
  );
  if (sensitiveCorrelatedEvents.length > 0) {
    const w = weights.sensitiveOutboundAfterOtp?.points ?? DEFAULT_WEIGHTS.sensitiveOutboundAfterOtp;
    contributions.push({
      ruleId: 'sensitiveOutboundAfterOtp',
      label: 'Sensitive-data exfiltration pattern',
      points: w,
      reason: `Sensitive field interacted before suspicious outbound request to "${sensitiveCorrelatedEvents[0].destinationHost}"`,
    });
    score += w;
  }

  // --- 7. Hidden suspicious iframe ---
  if (domAnalysis?.hiddenIframes.length > 0) {
    const w = weights.hiddenSuspiciousIframe?.points ?? DEFAULT_WEIGHTS.hiddenSuspiciousIframe;
    contributions.push({
      ruleId: 'hiddenSuspiciousIframe',
      label: 'Hidden / suspicious iframe',
      points: w,
      reason: `${domAnalysis.hiddenIframes.length} hidden iframe(s) detected`,
    });
    score += w;
  }

  // --- 8. Canary exfiltration attempt ---
  if (canaryResult?.transmissionDetected) {
    const w = weights.canaryExfiltrationAttempt?.points ?? DEFAULT_WEIGHTS.canaryExfiltrationAttempt;
    contributions.push({
      ruleId: 'canaryExfiltrationAttempt',
      label: 'Confirmed Canary exfiltration attempt',
      points: w,
      reason: 'Canary Probe detected attempted exfiltration of synthetic OTP token',
    });
    score += w;
  }

  // --- 9. Suspicious URL patterns ---
  if (urlAnalysis?.suspiciousPatterns && urlAnalysis.suspiciousPatterns.length > 0) {
    const w = weights.suspiciousUrlPattern?.points ?? DEFAULT_WEIGHTS.suspiciousUrlPattern;
    contributions.push({
      ruleId: 'suspiciousUrlPattern',
      label: 'Suspicious URL pattern',
      points: w,
      reason: urlAnalysis.suspiciousPatterns.join('; '),
    });
    score += w;
  }

  // --- 10. Insecure HTTP ---
  if (urlAnalysis && !urlAnalysis.isHttps) {
    const w = weights.insecureHttp?.points ?? DEFAULT_WEIGHTS.insecureHttp;
    contributions.push({
      ruleId: 'insecureHttp',
      label: 'Insecure HTTP',
      points: w,
      reason: 'Connection uses HTTP instead of HTTPS',
    });
    score += w;
  }

  // Cap score at 100
  score = Math.min(score, 100);
  const finalLevel = scoreToLevel(score);

  // Build human-readable explanation
  const explanation = buildExplanation(contributions, finalLevel);

  return {
    score,
    level: finalLevel,
    contributions,
    verdict: buildVerdict(finalLevel),
    explanation,
  };
}

function scoreToLevel(score: number): ThreatLevel {
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

function buildVerdict(level: ThreatLevel): string {
  switch (level) {
    case 'HIGH': return 'HIGH RISK - Suspicious behaviour detected';
    case 'MEDIUM': return 'MEDIUM RISK - Some suspicious indicators';
    case 'LOW': return 'LOW RISK - No significant indicators';
  }
}

function buildExplanation(
  contributions: RiskContribution[],
  level: ThreatLevel,
): string {
  if (contributions.length === 0) {
    return 'No suspicious indicators detected on this webpage.';
  }

  const topContributions = [...contributions]
    .sort((a, b) => b.points - a.points)
    .slice(0, 3);

  const parts = topContributions.map(c => `- ${c.label}: ${c.reason}`);
  const header = `Threat level: ${level}\nKey findings:\n`;
  return header + parts.join('\n');
}

// ---------------------------------------------------------------------------
// Helper: Is a destination domain suspicious?
// ---------------------------------------------------------------------------

function isDestinationSuspicious(destination: string): boolean {
  const suspiciousPatterns = ['attacker', 'collector', 'steal', 'exfiltrate',
    'malicious', 'data-grab', 'phish', 'capture'];
  const lower = destination.toLowerCase();
  return suspiciousPatterns.some(p => lower.includes(p)) ||
    lower.endsWith('.example') && lower.includes('attacker') ||
    lower.includes('.example') && suspiciousPatterns.some(p => lower.includes(p));
}

/**
 * Check if domain is in the known-malicious list (mirrored from URL analyzer).
 */
function isKnownMaliciousDomain(hostname: string): boolean {
  const knownMalicious = [
    'attacker.example',
    'collector.example',
    'steal.example',
    'exfiltrate.example',
    'malicious.example',
  ];
  return knownMalicious.some(d => hostname.includes(d));
}

/**
 * Generate a summary explanation string for display.
 */
export function getScoreSummary(assessment: RiskAssessment): string {
  return `Risk Score: ${assessment.score}/100 - ${assessment.level} - ${assessment.verdict}`;
}