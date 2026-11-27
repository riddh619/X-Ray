/**
 * URL Analyzer - Domain identity analysis
 * Detects homoglyphs, brand mismatches, suspicious URL patterns.
 * Uses Unicode UTS #39 confusables detection (simplified implementation).
 */

import type { BrandRegistryEntry, BrandMatch, UrlAnalysis } from '../types';
import brandRegistryJson from '../data/brand-registry.json';

// ---------------------------------------------------------------------------
// Unicode Confusable Detection (Simplified UTS #39)
// ---------------------------------------------------------------------------

/** Maps common homoglyph characters to their ASCII equivalents */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic
  'а': 'a', // Cyrillic a
  'е': 'e', // Cyrillic e
  'о': 'o', // Cyrillic o
  'р': 'p', // Cyrillic p
  'с': 'c', // Cyrillic c
  'у': 'y', // Cyrillic y
  'х': 'x', // Cyrillic x
  'і': 'i', // Cyrillic i
  'ѕ': 's', // Cyrillic s
  'һ': 'h', // Cyrillic h
  'ԛ': 'q', // Cyrillic q
  // Greek
  'α': 'a', // Greek alpha
  'β': 'b', // Greek beta
  'γ': 'y', // Greek gamma
  'ε': 'e', // Greek epsilon
  'ι': 'i', // Greek iota
  'ο': 'o', // Greek omicron
  'ρ': 'p', // Greek rho
  'τ': 't', // Greek tau
  'υ': 'u', // Greek upsilon
  'ν': 'v', // Greek nu
  'κ': 'k', // Greek kappa
  // Fullwidth
  'Ａ': 'A',
  'Ｂ': 'B',
  'Ｃ': 'C',
  'Ｄ': 'D',
  'Ｅ': 'E',
  'Ｆ': 'F',
  'Ｇ': 'G',
  'Ｈ': 'H',
  'Ｉ': 'I',
  'Ｊ': 'J',
  'Ｋ': 'K',
  'Ｌ': 'L',
  'Ｍ': 'M',
  'Ｎ': 'N',
  'Ｏ': 'O',
  'Ｐ': 'P',
  'Ｑ': 'Q',
  'Ｒ': 'R',
  'Ｓ': 'S',
  'Ｔ': 'T',
  'Ｕ': 'U',
  'Ｖ': 'V',
  'Ｗ': 'W',
  'Ｘ': 'X',
  'Ｙ': 'Y',
  'Ｚ': 'Z',
  'ａ': 'a',
  'ｂ': 'b',
  'ｃ': 'c',
  'ｄ': 'd',
  'ｅ': 'e',
  'ｆ': 'f',
  'ｇ': 'g',
  'ｈ': 'h',
  'ｉ': 'i',
  'ｊ': 'j',
  'ｋ': 'k',
  'ｌ': 'l',
  'ｍ': 'm',
  'ｎ': 'n',
  'ｏ': 'o',
  'ｐ': 'p',
  'ｑ': 'q',
  'ｒ': 'r',
  'ｓ': 's',
  'ｔ': 't',
  'ｕ': 'u',
  'ｖ': 'v',
  'ｗ': 'w',
  'ｘ': 'x',
  'ｙ': 'y',
  'ｚ': 'z',
  // Numeric confusables
  'Ͱ': 'p',
  'Α': 'A',
  'Ξ': 'E',
  // Other common ones
  ' ': ' ', // Non-breaking space
};

/**
 * Detect if a string contains characters that have visual
 * confusable equivalents in ASCII (homoglyphs).
 */
export function detectHomoglyphs(input: string): {
  hasHomoglyph: boolean;
  confusable: string;
  detail: string;
  position: number;
} {
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (HOMOGLYPH_MAP[ch]) {
      return {
        hasHomoglyph: true,
        confusable: HOMOGLYPH_MAP[ch],
        detail: `Character '${ch}' (U+${ch.codePointAt(0)?.toString(16).toUpperCase().padStart(4, '0')}) looks like '${HOMOGLYPH_MAP[ch]}'`,
        position: i,
      };
    }
  }
  return { hasHomoglyph: false, confusable: '', detail: '', position: -1 };
}

/**
 * Detect if a string mixes scripts (e.g. Latin + Cyrillic).
 */
export function detectMixedScript(input: string): { mixed: boolean; scripts: string[] } {
  const scripts = new Set<string>();
  for (const ch of input) {
    const code = ch.codePointAt(0)!;
    if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
      scripts.add('Latin');
    } else if (code >= 0x0370 && code <= 0x03FF) {
      scripts.add('Greek');
    } else if (code >= 0x0400 && code <= 0x04FF) {
      scripts.add('Cyrillic');
    } else if (code >= 0x0530 && code <= 0x058F) {
      scripts.add('Armenian');
    } else if (code >= 0x0590 && code <= 0x05FF) {
      scripts.add('Hebrew');
    } else if (code >= 0x0600 && code <= 0x06FF) {
      scripts.add('Arabic');
    } else if (code >= 0xFF00 && code <= 0xFFEF) {
      scripts.add('Fullwidth');
    } else if (code >= 0x4E00 && code <= 0x9FFF) {
      scripts.add('CJK');
    } else if (code >= 0x3040 && code <= 0x309F) {
      scripts.add('Hiragana');
    } else if (code >= 0x30A0 && code <= 0x30FF) {
      scripts.add('Katakana');
    } else if (code >= 0xAC00 && code <= 0xD7AF) {
      scripts.add('Hangul');
    } else if (code >= 0x0900 && code <= 0x097F) {
      scripts.add('Devanagari');
    }
  }
  // If we have 2+ scripts mixed together (excluding digits and Latin-as-common)
  return {
    mixed: scripts.size >= 2,
    scripts: Array.from(scripts),
  };
}

/**
 * Check for suspicious URL patterns.
 */
export function checkSuspiciousPatterns(
  hostname: string,
  pathname: string,
): string[] {
  const patterns: string[] = [];
  const fullUrl = hostname + pathname;

  // IP address in hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
      hostname === '[::1]' ||
      hostname.startsWith('[')) {
    patterns.push('URL uses IP address instead of domain name');
  }

  // Punycode / IDN
  if (hostname.includes('xn--')) {
    patterns.push('Domain contains punycode-encoded (IDN) characters');
  }

  // Excessive subdomains
  const subdomainParts = hostname.split('.');
  if (subdomainParts.length > 5) {
    patterns.push('Domain has excessive subdomain levels');
  }

  // Excessive hyphens
  if ((hostname.match(/-/g) || []).length >= 3) {
    patterns.push('Domain contains multiple hyphens');
  }

  // Brand keywords in subdomain (common phishing technique)
  const sensitiveKeywords = ['login', 'signin', 'verify', 'secure', 'account',
    'update', 'confirm', 'auth', 'banking', 'payment', 'wallet'];
  const subdomainLower = subdomainParts.slice(0, -2).join('.');
  for (const kw of sensitiveKeywords) {
    if (subdomainLower.toLowerCase().includes(kw)) {
      patterns.push(`Subdomain contains sensitive keyword "${kw}"`);
    }
  }

  // TLD spoofing (e.g. example.com.login.example)
  const tldPatterns = ['.com', '.net', '.org', '.edu', '.gov'];
  const partTlds = hostname.toLowerCase().split('.');
  for (let i = 1; i < partTlds.length - 1; i++) {
    const combined = partTlds[i] + '.' + partTlds[i + 1];
    if (tldPatterns.includes('.' + combined) &&
        hostname.split('.').length > 2) {
      patterns.push('Possible TLD spoofing in subdomain');
      break;
    }
  }

  // Non-standard port in URL
  if (pathname.includes(':')) {
    patterns.push('URL contains port specification');
  }

  // Credentials in URL (username:password@)
  if (fullUrl.includes('@') && fullUrl.split('@').length > 1 &&
      fullUrl.split('@')[0].includes(':')) {
    patterns.push('URL contains embedded credentials');
  }

  // Very long hostname
  if (hostname.length > 60) {
    patterns.push('Domain name is unusually long');
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// Brand Matching
// ---------------------------------------------------------------------------

let brandRegistryCache: BrandRegistryEntry[] | null = null;

async function loadBrandRegistry(): Promise<BrandRegistryEntry[]> {
  if (brandRegistryCache) return brandRegistryCache;
  if (brandRegistryJson && Array.isArray((brandRegistryJson as any).brands)) {
    brandRegistryCache = (brandRegistryJson as any).brands as BrandRegistryEntry[];
    return brandRegistryCache;
  }
  return [];
}

export async function analyzeUrl(rawUrl: string): Promise<UrlAnalysis> {
  const reasons: string[] = [];
  let riskContribution = 0;
  const suspiciousPatterns: string[] = [];

  // Parse URL safely
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return {
      rawUrl,
      hostname: '',
      registeredDomain: '',
      subdomain: '',
      protocol: '',
      isHttps: false,
      isIpAddress: false,
      hasPunycode: false,
      homoglyphRisk: false,
      mixedScriptRisk: false,
      suspiciousPatterns: ['Invalid or malformed URL'],
      brandMatch: null,
      riskContribution: 5,
      reasons: ['Invalid URL'],
    };
  }

  const hostname = url.hostname;
  const protocol = url.protocol;

  // Multi-part TLD aware registered domain extraction
  const multiPartTlds = ['co.uk', 'com.au', 'co.in', 'net.in', 'gov.in', 'org.uk', 'com.br', 'co.jp'];
  const parts = hostname.toLowerCase().split('.');
  let registeredDomain = hostname;
  let subdomain = '';

  if (parts.length > 2) {
    const lastTwo = parts.slice(-2).join('.');
    if (multiPartTlds.includes(lastTwo) && parts.length >= 3) {
      registeredDomain = parts.slice(-3).join('.');
      subdomain = parts.slice(0, -3).join('.');
    } else {
      registeredDomain = parts.slice(-2).join('.');
      subdomain = parts.slice(0, -2).join('.');
    }
  }

  // Check for homoglyphs
  const homoglyphResult = detectHomoglyphs(hostname);
  let homoglyphRisk = false;
  if (homoglyphResult.hasHomoglyph) {
    homoglyphRisk = true;
    riskContribution += 25;
    reasons.push(`Homoglyph detected in domain: ${homoglyphResult.detail}`);
    suspiciousPatterns.push(`Homoglyph: ${homoglyphResult.detail}`);
  }

  // Check for mixed scripts
  const scriptResult = detectMixedScript(hostname);
  let mixedScriptRisk = false;
  if (scriptResult.mixed) {
    mixedScriptRisk = true;
    // Only add risk if not already counted for homoglyph
    if (!homoglyphRisk) {
      riskContribution += 15;
      reasons.push(`Mixed script detected in domain: ${scriptResult.scripts.join(', ')}`);
    }
    suspiciousPatterns.push(`Mixed script: ${scriptResult.scripts.join(' + ')}`);
  }

  // Check suspicious patterns
  const patterns = checkSuspiciousPatterns(hostname, url.pathname);
  suspiciousPatterns.push(...patterns);
  for (const p of patterns) {
    reasons.push(p);
  }
  // Add a small risk bump for suspicious patterns
  if (patterns.length > 0) {
    riskContribution += Math.min(patterns.length * 5, 15);
  }

  // Check IP address
  const isIpAddress = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
    hostname === '[::1]' || hostname.startsWith('[');
  if (isIpAddress) {
    riskContribution += 15;
    reasons.push('Domain is an IP address (common phishing indicator)');
  }

  // Check punycode
  const hasPunycode = hostname.includes('xn--');
  if (hasPunycode && !homoglyphRisk) {
    riskContribution += 15;
    reasons.push('Domain contains punycode/IDN encoding (potential homoglyph attack)');
  }

  // HTTPS check
  const isHttps = protocol === 'https:';
  if (!isHttps) {
    riskContribution += 5;
    reasons.push('URL uses insecure HTTP (no encryption)');
  }

  // Brand matching
  const brandMatch = await matchBrand(hostname, url, registeredDomain, subdomain);

  return {
    rawUrl,
    hostname,
    registeredDomain,
    subdomain,
    protocol,
    isHttps,
    isIpAddress,
    hasPunycode,
    homoglyphRisk,
    homoglyphDetail: homoglyphResult.hasHomoglyph ? homoglyphResult.detail : undefined,
    mixedScriptRisk,
    suspiciousPatterns,
    brandMatch,
    riskContribution: Math.min(riskContribution, 100),
    reasons,
  };
}

async function matchBrand(
  hostname: string,
  url: URL,
  registeredDomain: string,
  subdomain: string,
): Promise<BrandMatch | null> {
  const registry = await loadBrandRegistry();
  if (registry.length === 0) return null;

  // Build search text from URL and hostname
  const searchText = (hostname + ' ' + url.pathname).toLowerCase();

  for (const brand of registry) {
    // Check if any brand keyword appears in the hostname or path
    let claimedBrand = false;
    for (const keyword of brand.keywords) {
      if (searchText.includes(keyword.toLowerCase())) {
        claimedBrand = true;
        break;
      }
    }

    // Also check brand ID in URL
    if (searchText.includes(brand.brandId.toLowerCase())) {
      claimedBrand = true;
    }

    if (!claimedBrand) continue;

    // Determine if the domain matches the official domain
    const domainMatches = registeredDomain === brand.officialDomain ||
      brand.aliases.includes(registeredDomain);

    return {
      brandId: brand.brandId,
      brandName: brand.brandName,
      officialDomain: brand.officialDomain,
      claimedBrand,
      domainMatches,
      mismatch: !domainMatches,
      confidence: domainMatches ? 0.95 : 0.85,
      reason: domainMatches
        ? `Domain matches verified domain for ${brand.brandName}`
        : `Page claims to be ${brand.brandName} but domain "${registeredDomain}" does not match verified domain "${brand.officialDomain}"`,
    };
  }

  return null;
}

/**
 * Quick check if a domain is in the local known-malicious list.
 */
export function isKnownMaliciousDomain(hostname: string): boolean {
  // In production, this would load from a local file or DNR ruleset.
  // For the simulation, we mark known attack domains.
  const knownMalicious = [
    'attacker.example',
    'collector.example',
    'steal.example',
    'exfiltrate.example',
    'malicious.example',
  ];
  return knownMalicious.some(d => hostname.includes(d));
}