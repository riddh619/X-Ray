/**
 * X-Ray Content Script (ISOLATED world) — WXT
 * DOM analysis, URL analysis, MAIN-world event validation and relay to background.
 * Runs in ISOLATED world — cannot directly access page's JavaScript APIs.
 */

import { defineContentScript } from 'wxt/sandbox'
import { analyzeDom } from '../modules/dom-analyzer'
import { analyzeUrl } from '../modules/url-analyzer'
import { assessRisk } from '../modules/risk-engine'
import type { MonitoredRequest, UrlAnalysis, DomAnalysis, RiskAssessment } from '../types'

export default defineContentScript({
  matches: ['<all_urls>'],
  world: 'ISOLATED',
  runAt: 'document_idle',
  main() {
    let currentUrlAnalysis: UrlAnalysis | null = null
    let currentDomAnalysis: DomAnalysis | null = null
    const monitoredRequests: MonitoredRequest[] = []

    async function runAnalysis(): Promise<void> {
      try {
        const url = window.location.href
        currentUrlAnalysis = await analyzeUrl(url)
        currentDomAnalysis = analyzeDom()
        const assessment = assessRisk(currentUrlAnalysis, currentDomAnalysis, monitoredRequests)

        await chrome.runtime.sendMessage({
          kind: 'XRAY_ANALYSIS_COMPLETE',
          payload: {
            urlAnalysis: currentUrlAnalysis,
            domAnalysis: currentDomAnalysis,
            assessment,
          },
        })
      } catch (e) {
        console.error('[X-Ray] Content script analysis error:', e)
      }
    }

    // Listen for commands from background worker (e.g. re-analyze)
    chrome.runtime.onMessage.addListener((message: any) => {
      if (message?.kind === 'XRAY_REANALYZE') {
        void runAnalysis()
      }
    })

    // Listen for events from MAIN-world instrumentation via window.postMessage
    // CRITICAL: Validate every event received through window.postMessage
    window.addEventListener('message', (event: MessageEvent) => {
      if (event.source !== window) return
      const m = event.data as any
      if (m?.kind !== 'XRAY_NETWORK_EVENT' || !m.payload || !m.payload.id) return

      const p = m.payload
      const safeEvent: MonitoredRequest = {
        id: String(p.id),
        api: p.api,
        method: p.method || 'GET',
        url: p.url || '',
        destinationHost: p.destinationHost || '',
        timestamp: p.timestamp || Date.now(),
        sourcePage: p.sourcePage || document.title || window.location.href,
        resourceType: p.resourceType || '',
        correlatedWithSensitiveInput: !!p.correlatedWithSensitiveInput,
      }

      monitoredRequests.push(safeEvent)
      if (monitoredRequests.length > 50) {
        monitoredRequests.shift()
      }

      // Forward validated event to background
      void chrome.runtime.sendMessage({
        kind: 'XRAY_NETWORK_EVENT',
        payload: safeEvent,
      })

      // If correlated with sensitive input, trigger risk reassessment
      if (safeEvent.correlatedWithSensitiveInput && currentUrlAnalysis && currentDomAnalysis) {
        const updatedAssessment = assessRisk(currentUrlAnalysis, currentDomAnalysis, monitoredRequests)
        void chrome.runtime.sendMessage({
          kind: 'XRAY_RISK_UPDATE',
          payload: { assessment: updatedAssessment },
        })
      }
    })

    // Run initial analysis when page is ready
    void runAnalysis()
  },
})
