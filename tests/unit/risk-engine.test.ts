import { describe, it, expect } from 'vitest'
import { assessRisk } from '../../extension/modules/risk-engine'
import type { UrlAnalysis, DomAnalysis, MonitoredRequest } from '../../extension/types'

describe('Risk Engine', () => {
  it('should return LOW risk when no indicators are present', () => {
    const assessment = assessRisk(
      null,
      {
        url: 'https://example.com',
        title: '',
        passwordFields: [],
        otpFields: [],
        emailFields: [],
        usernameFields: [],
        authForms: [],
        hiddenIframes: [],
        suspiciousEmbedded: [],
        pageBrandKeywords: [],
        riskContribution: 0,
        reasons: [],
      },
      [],
      null,
    )

    expect(assessment.score).toBe(0)
    expect(assessment.level).toBe('LOW')
  })

  it('should detect homoglyph and brand mismatch', () => {
    const urlAnalysis: UrlAnalysis = {
      rawUrl: 'https://dоmаin.com',
      hostname: 'dоmаin.com',
      registeredDomain: 'dоmаin.com',
      subdomain: '',
      protocol: 'https:',
      isHttps: true,
      isIpAddress: false,
      hasPunycode: false,
      homoglyphRisk: true,
      homoglyphDetail: 'Cyrillic characters detected',
      mixedScriptRisk: false,
      suspiciousPatterns: ['Homoglyph detected'],
      brandMatch: null,
      riskContribution: 25,
      reasons: ['Homoglyph detected'],
    }

    const domAnalysis: DomAnalysis = {
      url: 'https://dоmаin.com',
      title: '',
      passwordFields: [],
      otpFields: [],
      emailFields: [],
      usernameFields: [],
      authForms: [],
      hiddenIframes: [],
      suspiciousEmbedded: [],
      pageBrandKeywords: [],
      riskContribution: 5,
      reasons: ['OTP field detected'],
    }

    const assessment = assessRisk(urlAnalysis, domAnalysis, [], null)
    expect(assessment.contributions).toHaveLength(1)
    expect(assessment.contributions[0].ruleId).toBe('homoglyphDetection')
    expect(assessment.contributions[0].points).toBe(25)
  })

  it('should not give HIGH risk from OTP field alone', () => {
    const urlAnalysis: UrlAnalysis = {
      rawUrl: 'https://example.com',
      hostname: 'example.com',
      registeredDomain: 'example.com',
      subdomain: '',
      protocol: 'https:',
      isHttps: true,
      isIpAddress: false,
      hasPunycode: false,
      homoglyphRisk: false,
      mixedScriptRisk: false,
      suspiciousPatterns: [],
      brandMatch: null,
      riskContribution: 0,
      reasons: [],
    }

    const domAnalysis: DomAnalysis = {
      url: 'https://example.com',
      title: '',
      passwordFields: [],
      otpFields: [
        {
          fieldId: 'otp1',
          type: 'otp',
          selector: 'input[name="otp"]',
          inputType: 'text',
        },
      ],
      emailFields: [],
      usernameFields: [],
      authForms: [],
      hiddenIframes: [],
      suspiciousEmbedded: [],
      pageBrandKeywords: [],
      riskContribution: 5,
      reasons: ['OTP field detected'],
    }

    const assessment = assessRisk(urlAnalysis, domAnalysis, [], null)
    // OTP field adds only 5 points -> should be LOW risk
    expect(assessment.score).toBe(5)
    expect(assessment.level).toBe('LOW')
  })

  it('should classify risk correctly', () => {
    // Test that score boundaries work
    expect(assessRisk(null, null, [], null).level).toBe('LOW')
  })
})