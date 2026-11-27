/**
 * X-Ray MAIN-world Content Script (WXT with world: 'MAIN')
 *
 * Runs in the page's MAIN JavaScript world at document_start.
 * Instruments: fetch, XMLHttpRequest, sendBeacon, WebSocket.
 * Sends metadata events to ISOLATED content script via window.postMessage.
 *
 * CRITICAL SECURITY:
 * Never captures actual credential values, only metadata.
 * Validated by ISOLATED world before relay to background.
 */

import { defineContentScript } from 'wxt/sandbox'

export default defineContentScript({
  matches: ['<all_urls>'],
  world: 'MAIN',
  runAt: 'document_start',
  main() {
    interface XRayNetworkEvent {
      kind: 'XRAY_NETWORK_EVENT'
      payload: {
        id: string
        api: 'fetch' | 'xhr' | 'sendBeacon' | 'websocket'
        method: string
        url: string
        destinationHost: string
        timestamp: number
        sourcePage: string
        resourceType?: string
        correlatedWithSensitiveInput: boolean
        bodySizeHint?: number
      }
    }

    let recentSensitiveInteraction: {
      fieldType: 'password' | 'otp' | 'email' | 'username'
      timestamp: number
    } | null = null

    const SENSITIVE_WINDOW_MS = 5000

    function sendToContentScript(message: XRayNetworkEvent): void {
      try {
        window.postMessage(message, '*')
      } catch {
        // Silently ignore if window.postMessage fails
      }
    }

    function trackSensitiveInteraction(fieldType: 'password' | 'otp' | 'email' | 'username'): void {
      recentSensitiveInteraction = {
        fieldType,
        timestamp: Date.now(),
      }
    }

    function hasRecentSensitiveInteraction(): boolean {
      if (!recentSensitiveInteraction) return false
      return Date.now() - recentSensitiveInteraction.timestamp < SENSITIVE_WINDOW_MS
    }

    function setupSensitiveFieldListeners(): void {
      // Monitor focusin, input, and keyup on potential sensitive fields
      const handler = (e: Event) => {
        const target = e.target as HTMLInputElement
        if (target && target.tagName === 'INPUT') {
          const type = (target.type || '').toLowerCase()
          const autocomplete = (target.autocomplete || '').toLowerCase()
          const name = (target.name || '').toLowerCase()
          const id = (target.id || '').toLowerCase()

          if (type === 'password') {
            trackSensitiveInteraction('password')
          } else if (
            autocomplete === 'one-time-code' ||
            name.includes('otp') ||
            id.includes('otp') ||
            name.includes('code') ||
            id.includes('code') ||
            name.includes('pin')
          ) {
            trackSensitiveInteraction('otp')
          } else if (type === 'email' || name.includes('email') || name.includes('mail')) {
            trackSensitiveInteraction('email')
          } else if (name.includes('user') || name.includes('login') || autocomplete.includes('username')) {
            trackSensitiveInteraction('username')
          }
        }
      }

      document.addEventListener('focusin', handler, true)
      document.addEventListener('input', handler, true)
    }

    // ---------------------------------------------------------------------------
    // fetch() instrumentation
    // ---------------------------------------------------------------------------
    const originalFetch = window.fetch
    if (typeof originalFetch === 'function') {
      window.fetch = function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        try {
          let requestUrl = ''
          let method = 'GET'

          if (typeof input === 'string') {
            requestUrl = input
          } else if (input instanceof URL) {
            requestUrl = input.toString()
          } else if (input instanceof Request) {
            requestUrl = input.url
            method = input.method || 'GET'
          }

          if (init?.method) {
            method = init.method
          }

          if (requestUrl) {
            try {
              const url = new URL(requestUrl, window.location.href)
              // Monitor cross-origin or non-static requests
              const isSameOrigin = url.origin === window.location.origin
              const event: XRayNetworkEvent = {
                kind: 'XRAY_NETWORK_EVENT',
                payload: {
                  id: `evt_f_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
                  api: 'fetch',
                  method: method.toUpperCase(),
                  url: url.toString(),
                  destinationHost: url.hostname,
                  timestamp: Date.now(),
                  sourcePage: document.title || window.location.href,
                  resourceType: 'fetch',
                  correlatedWithSensitiveInput: hasRecentSensitiveInteraction(),
                },
              }
              // Send event if cross-origin or if correlated with sensitive interaction
              if (!isSameOrigin || event.payload.correlatedWithSensitiveInput) {
                sendToContentScript(event)
              }
            } catch {}
          }
        } catch {}

        return originalFetch.call(this, input, init)
      }
    }

    // ---------------------------------------------------------------------------
    // XMLHttpRequest instrumentation
    // ---------------------------------------------------------------------------
    const originalXHROpen = XMLHttpRequest.prototype.open
    const originalXHRSend = XMLHttpRequest.prototype.send

    XMLHttpRequest.prototype.open = function (
      method: string,
      url: string | URL,
      async?: boolean,
      username?: string | null,
      password?: string | null,
    ): void {
      ;(this as any).__xray_url__ = typeof url === 'string' ? url : String(url)
      ;(this as any).__xray_method__ = method || 'GET'
      return originalXHROpen.call(this, method, url, async !== false, username, password)
    }

    XMLHttpRequest.prototype.send = function (body?: Document | BodyInit | null): void {
      try {
        const urlStr = (this as any).__xray_url__
        const method = (this as any).__xray_method__ || 'GET'
        if (urlStr) {
          const url = new URL(urlStr, window.location.href)
          const isSameOrigin = url.origin === window.location.origin
          const event: XRayNetworkEvent = {
            kind: 'XRAY_NETWORK_EVENT',
            payload: {
              id: `evt_x_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
              api: 'xhr',
              method: method.toUpperCase(),
              url: url.toString(),
              destinationHost: url.hostname,
              timestamp: Date.now(),
              sourcePage: document.title || window.location.href,
              resourceType: 'xhr',
              correlatedWithSensitiveInput: hasRecentSensitiveInteraction(),
            },
          }
          if (!isSameOrigin || event.payload.correlatedWithSensitiveInput) {
            sendToContentScript(event)
          }
        }
      } catch {}

      return originalXHRSend.call(this, body)
    }

    // ---------------------------------------------------------------------------
    // sendBeacon instrumentation
    // ---------------------------------------------------------------------------
    if ('sendBeacon' in navigator) {
      const originalBeacon = navigator.sendBeacon.bind(navigator)
      navigator.sendBeacon = function (url: string | URL, data?: BodyInit | null): boolean {
        try {
          const parsedUrl = new URL(url.toString(), window.location.href)
          const isSameOrigin = parsedUrl.origin === window.location.origin
          const event: XRayNetworkEvent = {
            kind: 'XRAY_NETWORK_EVENT',
            payload: {
              id: `evt_b_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
              api: 'sendBeacon',
              method: 'POST',
              url: parsedUrl.toString(),
              destinationHost: parsedUrl.hostname,
              timestamp: Date.now(),
              sourcePage: document.title || window.location.href,
              resourceType: 'beacon',
              correlatedWithSensitiveInput: hasRecentSensitiveInteraction(),
            },
          }
          if (!isSameOrigin || event.payload.correlatedWithSensitiveInput) {
            sendToContentScript(event)
          }
        } catch {}

        return originalBeacon(url, data)
      }
    }

    // ---------------------------------------------------------------------------
    // WebSocket instrumentation
    // ---------------------------------------------------------------------------
    const originalWebSocket = window.WebSocket
    if (typeof originalWebSocket === 'function') {
      window.WebSocket = function (url: string | URL, protocols?: string | string[]): WebSocket {
        try {
          const parsedUrl = new URL(url.toString(), window.location.href)
          const event: XRayNetworkEvent = {
            kind: 'XRAY_NETWORK_EVENT',
            payload: {
              id: `evt_w_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
              api: 'websocket',
              method: 'GET',
              url: parsedUrl.toString(),
              destinationHost: parsedUrl.hostname,
              timestamp: Date.now(),
              sourcePage: document.title || window.location.href,
              resourceType: 'websocket',
              correlatedWithSensitiveInput: hasRecentSensitiveInteraction(),
            },
          }
          sendToContentScript(event)
        } catch {}

        return new originalWebSocket(url, protocols)
      } as any

      Object.setPrototypeOf(window.WebSocket, originalWebSocket)
      Object.setPrototypeOf(window.WebSocket.prototype, originalWebSocket.prototype)
    }

    // Initialize listeners
    setupSensitiveFieldListeners()
    ;(window as any).__xray_main_world_ready__ = true
    console.log('[X-Ray] MAIN-world network instrumentation active')
  },
})
