/**
 * X-Ray MAIN-world Content Script (WXT with world: 'MAIN')
 *
 * Runs in the page's MAIN JavaScript world.
 * Instruments: fetch, XMLHttpRequest, sendBeacon, WebSocket
 * Sends events to ISOLATED content script via window.postMessage
 *
 * CRITICAL: Events must be validated by the ISOLATED content script before processing.
 * The webpage MUST NOT be able to directly execute privileged extension actions.
 */

import { defineContentScript } from 'wxt/content-script'

// ---------------------------------------------------------------------------
// Types for messages sent to ISOLATED content script
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let recentSensitiveInteraction: {
  fieldType: 'password' | 'otp' | 'email' | 'username'
  timestamp: number
} | null = null

const SENSITIVE_WINDOW_MS = 3000

// ---------------------------------------------------------------------------
// Utility: Send event to ISOLATED content script via postMessage
// ---------------------------------------------------------------------------

function sendToContentScript(message: XRayNetworkEvent): void {
  try {
    // The 'window' inside MAIN-world content script IS the page's window
    ;(window as any).postMessage(message, '*')
  } catch {
    // Content script may not be ready - ignore
  }
}

// ---------------------------------------------------------------------------
// Track sensitive field interactions (from MAIN world)
// ---------------------------------------------------------------------------

function trackSensitiveInteraction(
  fieldType: 'password' | 'otp' | 'email' | 'username',
): void {
  recentSensitiveInteraction = {
    fieldType,
    timestamp: Date.now(),
  }

  setTimeout(() => {
    if (
      recentSensitiveInteraction &&
      Date.now() - recentSensitiveInteraction.timestamp > SENSITIVE_WINDOW_MS
    ) {
      recentSensitiveInteraction = null
    }
  }, SENSITIVE_WINDOW_MS)
}

// ---------------------------------------------------------------------------
// Check if recent sensitive interaction occurred
// ---------------------------------------------------------------------------

function hasRecentSensitiveInteraction(): boolean {
  return recentSensitiveInteraction !== null &&
    Date.now() - recentSensitiveInteraction.timestamp < SENSITIVE_WINDOW_MS
}

function getRecentSensitiveTypes(): Array<'password' | 'otp' | 'email' | 'username'> {
  if (!recentSensitiveInteraction) return []
  return [recentSensitiveInteraction.fieldType]
}

// ---------------------------------------------------------------------------
// Listen for focus/input events on sensitive fields (MAIN world)
// ---------------------------------------------------------------------------

function setupSensitiveFieldListeners(): void {
  // Listen for focus/click on inputs
  document.addEventListener('focusin', (e) => {
    const target = e.target as HTMLInputElement
    if (target?.tagName === 'INPUT') {
      const type = target.type
      const autocomplete = target.autocomplete
      const name = (target.name || '').toLowerCase()
      const id = (target.id || '').toLowerCase()

      if (type === 'password') {
        trackSensitiveInteraction('password')
      } else if (autocomplete === 'one-time-code' ||
                 name.includes('otp') || id.includes('otp')) {
        trackSensitiveInteraction('otp')
      } else if (type === 'email' || name.includes('email') || name.includes('mail')) {
        trackSensitiveInteraction('email')
      } else if (name.includes('user') || name.includes('login') ||
                 autocomplete.includes('username')) {
        trackSensitiveInteraction('username')
      }
    }
  }, true)
}

// ---------------------------------------------------------------------------
// fetch() instrumentation
// ---------------------------------------------------------------------------

const originalFetch = window.fetch

window.fetch = function (
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  try {
    const request = input instanceof Request ? input : new Request(input, init || {})
    const url = new URL(request.url as string)

    // Skip same-origin requests (reduce noise)
    if (url.origin === window.location.origin) {
      return originalFetch.call(this, input, init)
    }

    const event: XRayNetworkEvent = {
      kind: 'XRAY_NETWORK_EVENT',
      payload: {
        id: `evt_f_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        api: 'fetch',
        method: request.method || 'GET',
        url: request.url,
        destinationHost: url.hostname,
        timestamp: Date.now(),
        sourcePage: document.title || window.location.href,
        resourceType: request.resourceType || '',
        correlatedWithSensitiveInput: hasRecentSensitiveInteraction(),
      },
    }

    sendToContentScript(event)

    return originalFetch.call(this, input, init)
  } catch (e) {
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(this as any).__xray_url__ = typeof url === 'string' ? url : String(url)
  return originalXHROpen.call(this, method, url, async, username, password)
}

XMLHttpRequest.prototype.send = function (body?: Document | BodyInit | null): void {
  try {
    const urlStr = (this as any).__xray_url__
    if (!urlStr) {
      return originalXHRSend.call(this, body)
    }

    const url = new URL(urlStr, window.location.href)

    // Skip same-origin
    if (url.origin === window.location.origin) {
      return originalXHRSend.call(this, body)
    }

    // Track loadend event for completion
    this.addEventListener('loadend', () => {
      try {
        const event: XRayNetworkEvent = {
          kind: 'XRAY_NETWORK_EVENT',
          payload: {
            id: `evt_x_${Date.now()}_${Math.random().toString(36).slice(2)}`,
            api: 'xhr',
            method: (this as XMLHttpRequest).method || 'GET',
            url: (this as XMLHttpRequest).responseURL || urlStr,
            destinationHost: url.hostname,
            timestamp: Date.now(),
            sourcePage: document.title || window.location.href,
            resourceType: '',
            correlatedWithSensitiveInput: hasRecentSensitiveInteraction(),
          },
        }
        sendToContentScript(event)
      } catch (e) {
        // Ignore
      }
    }, { once: true })
  } catch (e) {
    // Ignore errors in instrumentation
  }

  return originalXHRSend.call(this, body)
}

// ---------------------------------------------------------------------------
// sendBeacon instrumentation
// ---------------------------------------------------------------------------

if ('sendBeacon' in navigator) {
  const originalBeacon = navigator.sendBeacon.bind(navigator)

  navigator.sendBeacon = function (url: string | URL, data?: string | ArrayBuffer | null): boolean {
    try {
      const parsedUrl = new URL(url.toString(), window.location.href)

      // Skip same-origin
      if (parsedUrl.origin === window.location.origin) {
        return originalBeacon(url, data)
      }

      const event: XRayNetworkEvent = {
        kind: 'XRAY_NETWORK_EVENT',
        payload: {
          id: `evt_b_${Date.now()}_${Math.random().toString(36).slice(2)}`,
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

      sendToContentScript(event)
    } catch (e) {
      // Ignore
    }

    return originalBeacon(url, data)
  }
}

// ---------------------------------------------------------------------------
// WebSocket instrumentation
// ---------------------------------------------------------------------------

const originalWebSocket = window.WebSocket

window.WebSocket = function (url: string | URL, protocols?: string | string[]): WebSocket {
  try {
    const ws = new originalWebSocket(url, protocols)
    const parsedUrl = new URL(url.toString(), window.location.href)

    // Skip same-origin
    if (parsedUrl.origin === window.location.origin) {
      return ws
    }

    const event: XRayNetworkEvent = {
      kind: 'XRAY_NETWORK_EVENT',
      payload: {
        id: `evt_w_${Date.now()}_${Math.random().toString(36).slice(2)}`,
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
    return ws
  } catch (e) {
    return new originalWebSocket(url, protocols)
  }
}

// Copy prototype properties
Object.setPrototypeOf(window.WebSocket, originalWebSocket)
Object.setPrototypeOf(window.WebSocket.prototype, originalWebSocket.prototype)

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

setupSensitiveFieldListeners()

// Signal to ISOLATED content script that MAIN world is active
;(window as any).__xray_main_world_ready__ = true

console.log('[X-Ray] MAIN-world instrumentation active (world: MAIN)')