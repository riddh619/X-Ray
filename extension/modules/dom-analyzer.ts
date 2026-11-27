/**
 * DOM Analyzer - Inspects webpage for sensitive inputs, forms, iframes
 * This runs in the ISOLATED world (content script).
 * Never stores actual field values - only metadata.
 */

import type {
  SensitiveFieldInfo,
  AuthFormInfo,
  HiddenIframeInfo,
  DomAnalysis,
} from '../types';

/**
 * Identify if an input field is likely an OTP field.
 * Never reads the actual value.
 */
export function isOtpField(input: HTMLInputElement): boolean {
  // autocomplete="one-time-code"
  if (input.autocomplete === 'one-time-code') return true;

  const name = (input.name || '').toLowerCase();
  const id = (input.id || '').toLowerCase();
  const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
  const placeholder = (input.placeholder || '').toLowerCase();

  const otpKeywords = ['otp', 'one-time', 'onetimecode', 'code', 'verification',
    'verify', 'sms', 'pin', 'auth-code'];

  for (const kw of otpKeywords) {
    if (name.includes(kw) || id.includes(kw) || ariaLabel.includes(kw)) {
      return true;
    }
    if (placeholder.includes(kw)) return true;
  }

  // Common input patterns for OTP (6-digit, 4-digit)
  const pattern = input.getAttribute('pattern') || input.getAttribute('inputmode');
  if (pattern) {
    if (/\d{4,8}/.test(pattern) || /\d{4,8}/.test(input.maxLength?.toString() || '')) {
      return true;
    }
  }
  if (input.maxLength === 4 || input.maxLength === 6 || input.maxLength === 8) {
    // Short numeric-only fields are often OTP
    if (input.type === 'tel' || input.type === 'number' || input.type === 'text') {
      return true;
    }
  }

  return false;
}

function isPasswordField(input: HTMLInputElement): boolean {
  return input.type === 'password';
}

function isEmailField(input: HTMLInputElement): boolean {
  if (input.type === 'email') return true;
  const name = (input.name || '').toLowerCase();
  const autocomplete = input.autocomplete || '';
  return name.includes('email') || name.includes('mail') ||
    autocomplete.includes('email');
}

function isUsernameField(input: HTMLInputElement): boolean {
  const name = (input.name || '').toLowerCase();
  const autocomplete = input.autocomplete || '';
  const id = (input.id || '').toLowerCase();
  return name.includes('user') || name.includes('login') || name.includes('account') ||
    autocomplete.includes('username') || id.includes('username') ||
    id.includes('login');
}

/**
 * Generate a CSS selector for an element.
 */
function getSelector(el: HTMLElement): string {
  if (el.id) return `#${el.id}`;
  const name = (el as HTMLInputElement).name;
  if (name) return `[name="${name}"]`;
  if (el.getAttribute('type')) return `input[type="${el.getAttribute('type')}"]`;
  return el.tagName.toLowerCase();
}

function extractFieldInfo(input: HTMLInputElement): SensitiveFieldInfo {
  let type: SensitiveFieldInfo['type'] = 'other';
  if (isPasswordField(input)) type = 'password';
  else if (isOtpField(input)) type = 'otp';
  else if (isEmailField(input)) type = 'email';
  else if (isUsernameField(input)) type = 'username';

  return {
    fieldId: input.id || `field_${Math.random().toString(36).substr(2, 9)}`,
    type,
    selector: getSelector(input),
    inputType: input.type,
    autocomplete: input.autocomplete || undefined,
    name: input.name || undefined,
    id: input.id || undefined,
    ariaLabel: input.getAttribute('aria-label') || undefined,
    placeholder: input.placeholder || undefined,
  };
}

/**
 * Extract brand-related keywords from page content.
 */
function extractPageBrandKeywords(): string[] {
  const keywords: string[] = [];
  const title = document.title;
  if (title) keywords.push(title);

  // Check meta tags
  document.querySelectorAll('meta[name="description"]').forEach(meta => {
    const content = meta.getAttribute('content');
    if (content) keywords.push(content);
  });
  document.querySelectorAll('meta[property="og:title"]').forEach(meta => {
    const content = meta.getAttribute('content');
    if (content) keywords.push(content);
  });
  document.querySelectorAll('meta[property="og:site_name"]').forEach(meta => {
    const content = meta.getAttribute('content');
    if (content) keywords.push(content);
  });

  // Check h1, h2 headers
  document.querySelectorAll('h1, h2').forEach(h => {
    keywords.push(h.textContent || '');
  });

  return keywords.filter(k => k.trim().length > 0);
}

/**
 * Analyze the entire DOM for security-relevant elements.
 */
export function analyzeDom(): DomAnalysis {
  const passwordFields: SensitiveFieldInfo[] = [];
  const otpFields: SensitiveFieldInfo[] = [];
  const emailFields: SensitiveFieldInfo[] = [];
  const usernameFields: SensitiveFieldInfo[] = [];
  const authForms: AuthFormInfo[] = [];
  const hiddenIframes: HiddenIframeInfo[] = [];
  const suspiciousEmbedded: string[] = [];
  const reasons: string[] = [];
  let riskContribution = 0;

  // Scan all input elements
  const allInputs = document.querySelectorAll('input');
  allInputs.forEach(input => {
    const info = extractFieldInfo(input);
    switch (info.type) {
      case 'password':
        passwordFields.push(info);
        break;
      case 'otp':
        otpFields.push(info);
        riskContribution += 5;
        reasons.push(`OTP field detected: ${info.selector} (${info.inputType})`);
        break;
      case 'email':
        emailFields.push(info);
        break;
      case 'username':
        usernameFields.push(info);
        break;
    }
  });

  // Analyze forms
  const forms = document.querySelectorAll('form');
  forms.forEach((form, idx) => {
    const action = form.getAttribute('action') || '';
    const method = form.getAttribute('method') || 'GET';

    // Check if form has password or OTP inputs
    const formInputs = form.querySelectorAll('input');
    let hasPassword = false;
    let hasOtp = false;
    let hasEmail = false;
    formInputs.forEach(input => {
      const info = extractFieldInfo(input as HTMLInputElement);
      if (info.type === 'password') hasPassword = true;
      if (info.type === 'otp') hasOtp = true;
      if (info.type === 'email') hasEmail = true;
    });

    // Check if action is external
    let isExternalAction = false;
    if (action && action !== '' && action !== '#') {
      try {
        const actionUrl = new URL(action, window.location.href);
        isExternalAction = actionUrl.hostname !== window.location.hostname;
      } catch {
        isExternalAction = true;
      }
    }

    authForms.push({
      formId: form.id || `form_${idx}`,
      action,
      isExternalAction,
      method,
      hasPassword,
      hasOtp,
      hasEmail,
    });

    if (isExternalAction) {
      riskContribution += 10;
      reasons.push(`Form "${form.id || 'unnamed'}" has external action: ${action}`);
    }
    if (hasPassword && hasOtp) {
      reasons.push(`Form "${form.id || 'unnamed'}" combines password and OTP fields`);
    }
  });

  // Check for hidden iframes
  const iframes = document.querySelectorAll('iframe');
  iframes.forEach(iframe => {
    const src = iframe.src || iframe.getAttribute('src') || '';
    const isHidden =
      iframe.style.display === 'none' ||
      iframe.style.visibility === 'hidden' ||
      iframe.width === '0' ||
      iframe.height === '0' ||
      iframe.offsetWidth === 0 ||
      iframe.offsetHeight === 0 ||
      iframe.getAttribute('hidden') !== null;

    if (isHidden) {
      const iframeReasons: string[] = [];
      iframeReasons.push('Hidden iframe (display:none or zero-sized)');

      if (src) {
        try {
          const srcUrl = new URL(src);
          if (srcUrl.hostname !== window.location.hostname) {
            iframeReasons.push(`Points to external domain: ${srcUrl.hostname}`);
            riskContribution += 10;
          }
        } catch {
          iframeReasons.push(`Points to suspicious/invalid URL: ${src}`);
          riskContribution += 10;
        }
      }

      hiddenIframes.push({ src, reasons: iframeReasons });
    }
  });

  // Check for suspicious embedded scripts
  const scripts = document.querySelectorAll('script');
  scripts.forEach(script => {
    const src = script.src || '';
    if (src) {
      // Flag scripts loaded from suspicious-looking domains
      try {
        const srcUrl = new URL(src);
        const suspiciousPatterns = ['collector', 'track', 'analytics-', 'beacon',
          'pixel', 'exfil', 'data-', 'grab', 'capture'];
        for (const pattern of suspiciousPatterns) {
          if (srcUrl.hostname.includes(pattern)) {
            suspiciousEmbedded.push(src);
            reasons.push(`Suspicious script loaded from: ${srcUrl.hostname}`);
            riskContribution += 5;
            break;
          }
        }
      } catch {
        // Invalid URL - flag it
        suspiciousEmbedded.push(src);
      }
    }
  });

  // Brand keywords
  const pageBrandKeywords = extractPageBrandKeywords();

  return {
    url: window.location.href,
    title: document.title || '',
    passwordFields,
    otpFields,
    emailFields,
    usernameFields,
    authForms,
    hiddenIframes,
    suspiciousEmbedded,
    pageBrandKeywords,
    riskContribution: Math.min(riskContribution, 100),
    reasons,
  };
}

/**
 * Set up a MutationObserver to watch for sensitive fields being added dynamically.
 * Returns a cleanup function.
 */
export function watchForSensitiveFields(
  callback: (field: SensitiveFieldInfo) => void,
): () => void {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of Array.from(mutation.addedNodes)) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const el = node as Element;
          // Check if this element is an input
          if (el.tagName === 'INPUT') {
            const info = extractFieldInfo(el as HTMLInputElement);
            if (info.type === 'password' || info.type === 'otp' ||
                info.type === 'email' || info.type === 'username') {
              callback(info);
            }
          }
          // Check for inputs inside added elements
          el.querySelectorAll('input').forEach(input => {
            const info = extractFieldInfo(input as HTMLInputElement);
            if (info.type === 'password' || info.type === 'otp' ||
                info.type === 'email' || info.type === 'username') {
              callback(info);
            }
          });
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  return () => observer.disconnect();
}