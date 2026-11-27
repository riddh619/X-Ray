/**
 * X-Ray Background Service Worker (WXT)
 * Coordinates monitoring, risk assessment, storage, and browser actions.
 */

import { defineBackground } from 'wxt/sandbox'
import type { ForensicsEvent, ProtectionSettings, TabState } from '../types'
import {
  initDnrRules,
  attachDebugger,
  detachDebugger,
  isStrictModeActive,
} from '../modules/network-interceptor'
import { getConsent, setConsent, ConsentCategories } from '../modules/approval-manager'

export default defineBackground(() => {
  const STORAGE = {
    EVENTS: (tabId: number) => `xray_events_${tabId}`,
    STATE: (tabId: number) => `xray_state_${tabId}`,
    SETTINGS: 'xray_settings',
    CONSENTS: 'xray_consent',
  }

  const DEFAULT_SETTINGS: ProtectionSettings = {
    basicProtection: true,
    strictProtection: false,
    privacyMode: false,
    externalAiConsent: false,
    monitoringEnabled: true,
    scoringRules: [],
  }

  // ---- Lifecycle ----
  chrome.runtime.onInstalled.addListener(async () => {
    await initDnrRules()
    await chrome.storage.local.set({
      [STORAGE.SETTINGS]: DEFAULT_SETTINGS,
      [STORAGE.CONSENTS]: {},
    })
  })

  // ---- Tab lifecycle ----
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
    if (changeInfo.status === 'complete' || changeInfo.url) {
      // Ensure the content script (re)initializes on navigation
      try {
        await chrome.tabs.sendMessage(tabId, { kind: 'XRAY_REANALYZE' })
      } catch {
        // Content script may not be present yet - it will self-initialize
      }
    }
  })

  // ---- Message handling ----
  chrome.runtime.onMessage.addListener(
    async (message: any, sender: chrome.runtime.MessageSender, sendResponse) => {
      const tabId = sender.tab?.id || 0
      try {
        switch (message?.kind) {
          case 'XRAY_ANALYSIS_COMPLETE': {
            const { assessment, urlAnalysis, domAnalysis } = message.payload
            const state: TabState = {
              tabId,
              url: urlAnalysis?.rawUrl || '',
              hostname: urlAnalysis?.hostname || '',
              title: domAnalysis?.title || '',
              riskScore: assessment.score,
              threatLevel: assessment.level,
              monitoringActive: true,
              strictActive: false,
              lastAnalysis: Date.now(),
              urlAnalysis,
              domAnalysis,
              events: [],
            }
            await chrome.storage.local.set({ [STORAGE.STATE(tabId)]: state })
            sendResponse({ success: true, assessment })
            break
          }

          case 'XRAY_NETWORK_EVENT': {
            const p = message.payload
            const event: ForensicsEvent = {
              id: p.id || `evt_${Date.now()}`,
              timestamp: p.timestamp || Date.now(),
              sourcePage: p.sourcePage || 'unknown',
              tabId,
              category: 'network_request',
              api: p.api,
              method: p.method,
              destination: p.destinationHost,
              riskContribution: p.correlatedWithSensitiveInput ? 30 : 0,
              detectionReason: p.correlatedWithSensitiveInput
                ? 'Sensitive data outflow after interaction'
                : 'Network activity observed',
              actionTaken: 'monitored',
            }
            const key = STORAGE.EVENTS(tabId)
            const stored = (await chrome.storage.local.get(key))[key] || []
            stored.push(event)
            await chrome.storage.local.set({ [key]: stored.slice(-100) })
            break
          }

          case 'XRAY_RISK_UPDATE': {
            const { assessment } = message.payload
            const key = STORAGE.STATE(tabId)
            const existing = (await chrome.storage.local.get(key))[key]
            if (existing) {
              existing.riskScore = assessment.score
              existing.threatLevel = assessment.level
              existing.lastAnalysis = Date.now()
              await chrome.storage.local.set({ [key]: existing })
            }

            // Auto-block signal for HIGH risk under strict mode
            if (isStrictModeActive() && assessment.level === 'HIGH') {
              const hasThreat = assessment.contributions?.some((c: any) =>
                ['knownMaliciousDomain', 'sensitiveOutboundAfterOtp', 'canaryExfiltrationAttempt'].includes(c.ruleId),
              )
              if (hasThreat) {
                console.log('[X-Ray] Strict mode: HIGH risk threat detected')
              }
            }
            break
          }

          case 'XRAY_TOGGLE_STRICT': {
            const enabled = !!message.payload?.enabled
            const settings = (await getSettings()) as ProtectionSettings
            settings.strictProtection = enabled
            await chrome.storage.local.set({ [STORAGE.SETTINGS]: settings })

            if (enabled) {
              const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
              if (tabs[0]?.id != null) {
                const attached = await attachDebugger(tabs[0].id)
                if (!attached) {
                  settings.strictProtection = false
                  await chrome.storage.local.set({ [STORAGE.SETTINGS]: settings })
                  console.warn('[X-Ray] Debugger unavailable - Strict mode disabled')
                }
              }
            } else {
              await detachDebugger()
            }
            break
          }

          case 'XRAY_SET_SETTINGS': {
            const current = (await getSettings()) as ProtectionSettings
            await chrome.storage.local.set({
              [STORAGE.SETTINGS]: { ...current, ...message.payload },
            })
            break
          }

          case 'XRAY_APPROVE_CONSENT': {
            const { key, granted } = message.payload
            await setConsent(key, granted, 'user_approved')
            break
          }

          case 'XRAY_GET_STATE': {
            let targetTabId = message.payload?.tabId || sender.tab?.id || 0
            if (!targetTabId) {
              const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true })
              targetTabId = activeTabs[0]?.id || 0
            }
            const key = STORAGE.STATE(targetTabId)
            const state = (await chrome.storage.local.get(key))[key]
            const eventsKey = STORAGE.EVENTS(targetTabId)
            const events = (await chrome.storage.local.get(eventsKey))[eventsKey] || []
            const settings = await getSettings()
            sendResponse({ state: state || null, events, settings, strictActive: isStrictModeActive() })
            break
          }

          default:
            break
        }
      } catch (e: any) {
        console.error('[X-Ray] Background error:', e)
        sendResponse({ error: e?.message })
      }
      return true
    },
  )

  async function getSettings(): Promise<ProtectionSettings> {
    const result = await chrome.storage.local.get(STORAGE.SETTINGS)
    return result[STORAGE.SETTINGS] || DEFAULT_SETTINGS
  }
})