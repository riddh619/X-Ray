/**
 * X-Ray Content Script (ISOLATED world) — WXT
 * DOM analysis, URL analysis, MAIN-world event validation and relay to background.
 * Runs in ISOLATED world — cannot directly access page's JavaScript APIs.
 */

import { defineContentScript } from 'wxt/content-script'
import { analyzeDom } from '../modules/dom-analyzer'
import { analyzeUrl } from '../modules/url-analyzer'
import { assessRisk } from '../modules/risk-engine'

export default defineContentScript({
  matches: ['<all_urls>'],
  world: 'ISOLATED',
  runAt: 'document_idle',
  main(ctx) {
    // --- Message forwarding from MAIN world ---
    // MAIN world sends events via window.postMessage; we validate them here.
    ctx.runtime.onMessage.addListener((message: any, sender) => {
      if (message?.kind === 'XRAY_REANALYZE') {
        void runAnalysis()
      }
    })

    // Also listen for inline postMessage from page (MAIN world -> ISOLATED)
    // Main-world script sends events; validate and forward
    let messageHandler: (event: MessageEvent) => void
    messageHandler = (event: MessageEvent) => {
      if (event.source !== window) return
      const m = event.data as any
      if (m?.kind !== 'XRAY_NETWORK_EVENT') return
      // Validate minimal structure
      if (!m.payload || !m.payload.id) return
      // Forward validated event to background
      void ctx.runtime.sendMessage({
        kind: 'XRAY_NETWORK_EVENT',
        payload: m.payload,
      })
    }
    window.addEventListener('message', messageHandler)

    // --- Initial analysis ---
    void runAnalysis()
  },
})

// ---------------------------------------------------------------------------
// Core analysis functions
// ---------------------------------------------------------------------------

async function runAnalysis(): Promise<void> {
  try {
    // 1. URL analysis (ISOLATED world can use URL API safely)
    const url = window.location.href
    const urlAnalysis = await analyzeUrl(url)

    // 2. DOM analysis (ISOLATED world can inspect DOM)
    const domAnalysis = analyzeDom()

    // 3. Initial risk assessment
    const assessment = assessRisk(urlAnalysis, domAnalysis, [])

    // 4. Send complete analysis to background
    void ctx.runtime.sendMessage({
      kind: 'XRAY_ANALYSIS_COMPLETE',
      payload: { urlAnalysis, domAnalysis, assessment },
    })
  } catch (e) {
    console.error('[X-Ray] Content script analysis error:', e)
  }
}

// ---------------------------------------------------------------------------
// Exports for module system compatibility
// ---------------------------------------------------------------------------

// The main() closure above captures ctx; we also need runtime access for background sync.
// ctx.runtime is provided by WXT's defineContentScript; export nothing needed externally.