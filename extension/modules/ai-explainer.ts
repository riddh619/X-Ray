/**
 * AI-Assisted Explanation Engine
 *
 * Default: local deterministic template engine (no external API required).
 * Optional: configurable LLM provider via environment variable.
 *
 * SECURITY: Never send passwords, OTPs, or sensitive form content to an AI provider.
 * External evidence sharing requires explicit user consent.
 * LLM may only explain evidence - it never approves or executes security actions.
 */

import type { RiskAssessment, UrlAnalysis, DomAnalysis, MonitoredRequest } from '../types';

// ---------------------------------------------------------------------------
// Sanitized evidence structure (safe to send to a remote provider)
// ---------------------------------------------------------------------------

export interface SanitizedEvidence {
  hostname: string;
  registeredDomain: string;
  threatLevel: string;
  riskScore: number;
  ruleIds: string[];
  reasons: string[];
  hasOtpField: boolean;
  hasPasswordField: boolean;
  suspiciousDestinations: string[];
  hasHiddenIframe: boolean;
  canaryDetected: boolean;
}

export function buildSanitizedEvidence(
  assessment: RiskAssessment,
  urlAnalysis: UrlAnalysis | null,
  domAnalysis: DomAnalysis | null,
  networkEvents: MonitoredRequest[],
): SanitizedEvidence {
  const suspiciousDestinations = networkEvents
    .filter(e => isSuspiciousDestination(e.destinationHost))
    .map(e => e.destinationHost);

  return {
    hostname: urlAnalysis?.hostname || '',
    registeredDomain: urlAnalysis?.registeredDomain || '',
    threatLevel: assessment.level,
    riskScore: assessment.score,
    ruleIds: assessment.contributions.map(c => c.ruleId),
    reasons: assessment.contributions.map(c => c.reason),
    hasOtpField: (domAnalysis?.otpFields.length || 0) > 0,
    hasPasswordField: (domAnalysis?.passwordFields.length || 0) > 0,
    suspiciousDestinations: Array.from(new Set(suspiciousDestinations)),
    hasHiddenIframe: (domAnalysis?.hiddenIframes.length || 0) > 0,
    canaryDetected: assessment.contributions.some(c => c.ruleId === 'canaryExfiltrationAttempt'),
  };
}

function isSuspiciousDestination(host: string): boolean {
  const patterns = ['attacker', 'collector', 'steal', 'exfiltrate', 'malicious', 'phish'];
  return patterns.some(p => host.toLowerCase().includes(p));
}

// ---------------------------------------------------------------------------
// Deterministic Template Engine
// ---------------------------------------------------------------------------

interface TemplateContext {
  hostname: string;
  registeredDomain: string;
  brandName?: string;
  officialDomain?: string;
  otpCount: number;
  passwordCount: number;
  suspiciousDestinations: string[];
  hasHiddenIframe: boolean;
  canaryDetected: boolean;
  threatLevel: string;
  mismatch: boolean;
  homoglyph: boolean;
}

function buildTemplateExplanation(ctx: TemplateContext): string {
  const lines: string[] = [];

  if (ctx.threatLevel === 'LOW') {
    lines.push('This page appears safe. No suspicious behaviour patterns were observed.');
    if (ctx.otpCount > 0 || ctx.passwordCount > 0) {
      lines.push(
        `The page does contain authentication fields ` +
        `(${ctx.passwordCount} password, ${ctx.otpCount} OTP), which is expected for login pages. ` +
        `However, no evidence of exfiltration or impersonation was found.`
      );
    }
    return lines.join('\n\n');
  }

  // Threat detected
  if (ctx.mismatch && ctx.brandName) {
    lines.push(
      `This webpage claims to belong to "${ctx.brandName}", but its registered domain ` +
      `("${ctx.registeredDomain}") does not match the verified official domain (` +
      `"${ctx.officialDomain}"). This is a common brand impersonation technique.`
    );
  }

  if (ctx.homoglyph) {
    lines.push(
      `The domain contains visually confusable characters (homoglyphs) that mimic ` +
      `the appearance of legitimate letters. This is a classic phishing technique ` +
      `used to make malicious URLs look familiar.`
    );
  }

  if (ctx.suspiciousDestinations.length > 0) {
    lines.push(
      `Outgoing network requests were observed to suspicious destination(s): ` +
      `${ctx.suspiciousDestinations.join(', ')}. These destinations are not ` +
      `associated with legitimate banking services.`
    );
  }

  if (ctx.otpCount > 0 && ctx.suspiciousDestinations.length > 0) {
    lines.push(
      `An OTP input field was detected on this page, and suspicious outbound ` +
      `network activity occurred shortly after. This combination strongly suggests ` +
      `an attempt to exfiltrate one-time codes.`
    );
  }

  if (ctx.canaryDetected) {
    lines.push(
      `A Canary Probe confirmed that this page attempts to transmit synthetic OTP ` +
      `data to an unauthorized destination. This is direct evidence of data exfiltration.`
    );
  }

  if (ctx.hasHiddenIframe) {
    lines.push(
      `Hidden iframes were detected on the page. These can be used to load ` +
      `malicious tracking scripts that operate without the user's knowledge.`
    );
  }

  if (ctx.threatLevel === 'HIGH') {
    lines.push(
      'RECOMMENDATION: Do not enter any credentials or personal information on this page. ' +
      'X-Ray strongly recommends closing this tab or navigating to the official website directly.'
    );
  } else if (ctx.threatLevel === 'MEDIUM') {
    lines.push(
      'RECOMMENDATION: Exercise caution. Some indicators of suspicious behaviour ' +
      'were observed. Verify the website address before entering any credentials.'
    );
  }

  return lines.join('\n\n');
}

// ---------------------------------------------------------------------------
// Advanced Template with Language Support (extensible)
// ---------------------------------------------------------------------------

export type ExplanationLanguage = 'en' | 'hi' | 'kn';

function buildLocalizedExplanation(ctx: TemplateContext, lang: ExplanationLanguage): string {
  // English is primary - other languages are placeholders for future extension
  switch (lang) {
    case 'hi':
      // Future: Hindi explanation
      // For now, fall back to English with a note
      return buildTemplateExplanation(ctx) + '\n\n[Hindi translation coming soon]';
    case 'kn':
      return buildTemplateExplanation(ctx) + '\n\n[Kannada translation coming soon]';
    default:
      return buildTemplateExplanation(ctx);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ExplanationOptions {
  language?: ExplanationLanguage;
  externalAiConsent?: boolean;
  apiKey?: string;
  provider?: 'openai' | 'anthropic' | 'local';
}

/**
 * Generate an explanation for the given risk assessment.
 * Always runs the local deterministic engine first.
 * If an external AI provider is configured AND consent is given,
 * optional enriched explanation can be requested.
 */
export async function explain(
  assessment: RiskAssessment,
  urlAnalysis: UrlAnalysis | null,
  domAnalysis: DomAnalysis | null,
  networkEvents: MonitoredRequest[],
  options: ExplanationOptions = {},
): Promise<string> {
  const ctx: TemplateContext = {
    hostname: urlAnalysis?.hostname || '',
    registeredDomain: urlAnalysis?.registeredDomain || '',
    brandName: urlAnalysis?.brandMatch?.brandName,
    officialDomain: urlAnalysis?.brandMatch?.officialDomain,
    otpCount: domAnalysis?.otpFields.length || 0,
    passwordCount: domAnalysis?.passwordFields.length || 0,
    suspiciousDestinations: networkEvents
      .filter(e => isSuspiciousDestination(e.destinationHost))
      .map(e => e.destinationHost),
    hasHiddenIframe: (domAnalysis?.hiddenIframes.length || 0) > 0,
    canaryDetected: assessment.contributions.some(c => c.ruleId === 'canaryExfiltrationAttempt'),
    threatLevel: assessment.level,
    mismatch: urlAnalysis?.brandMatch?.mismatch || false,
    homoglyph: urlAnalysis?.homoglyphRisk || false,
  };

  // Local deterministic explanation
  const localExplanation = buildLocalizedExplanation(ctx, options.language || 'en');

  // If no external AI or no consent, return local
  if (!options.apiKey || !options.externalAiConsent) {
    return localExplanation;
  }

  // External AI - send only sanitized evidence
  try {
    const sanitized = buildSanitizedEvidence(assessment, urlAnalysis, domAnalysis, networkEvents);
    const remoteExplanation = await callExternalAI(sanitized, options);
    if (remoteExplanation && remoteExplanation.trim().length > 0) {
      return localExplanation + '\n\n---\nAI-enhanced explanation:\n' + remoteExplanation;
    }
  } catch (e) {
    console.warn('[X-Ray] External AI explanation failed, using local:', e);
  }

  // Fall back to local on any error
  return localExplanation;
}

// ---------------------------------------------------------------------------
// External AI Integration (Optional)
// ---------------------------------------------------------------------------

async function callExternalAI(
  evidence: SanitizedEvidence,
  options: ExplanationOptions,
): Promise<string | null> {
  const prompt = `You are a cybersecurity analyst assistant. Explain the following sanitized webpage security evidence to a non-technical user in clear, calm language. Do not invent facts beyond the evidence. Do not recommend specific security actions as commands; you may explain risks. Evidence: ${JSON.stringify(evidence, null, 2)}`;

  switch (options.provider) {
    case 'openai':
      return callOpenAI(prompt, options.apiKey!);
    case 'anthropic':
      return callAnthropic(prompt, options.apiKey!);
    default:
      return null;
  }
}

async function callOpenAI(prompt: string, apiKey: string): Promise<string | null> {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 300,
        temperature: 0.2,
      }),
    });
    if (!response.ok) return null;
    const data = await response.json();
    return data.choices?.[0]?.message?.content || null;
  } catch (e) {
    console.warn('[X-Ray] OpenAI call failed:', e);
    return null;
  }
}

async function callAnthropic(prompt: string, apiKey: string): Promise<string | null> {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-3-5-haiku-20241022',
        max_tokens: 300,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    if (!response.ok) return null;
    const data = await response.json();
    return data.content?.[0]?.text || null;
  } catch (e) {
    console.warn('[X-Ray] Anthropic call failed:', e);
    return null;
  }
}