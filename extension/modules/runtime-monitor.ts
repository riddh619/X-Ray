/**
 * Runtime Monitoring Engine - Instruments MAIN-world JavaScript APIs
 *
 * IMPORTANT: MAIN-world monkey-patching is bypassable.
 * This provides detection capability but not absolute network visibility.
 * Events must be validated - never trust raw MAIN-world events unconditionally.
 *
 * This module monkey-patches fetch, XHR, sendBeacon, and WebSocket.
 * It captures metadata only - never captures request bodies with credentials.
 */

import type {
  MonitoredRequest,
  NetworkApi,
  ForensicsEvent,
  EventCategory,
  RiskContribution,
} from '../types';

// ---------------------------------------------------------------------------
// Storage reference - will be injected from background
// ---------------------------------------------------------------------------

let storageRef: chrome.storage.Storage | null = null;
function setStorage(storage: chrome.storage.Storage) {
  storageRef = storage;
}

/** In-memory buffer for monitored events per tab */
const monitoredBuffer = new Map<number, MonitoredRequest[]>(); // tabId -> events

/**
 * Reset buffer for a tab when it unloads.
 */
function cleanupTab(tabId: number) {
  monitoredBuffer.delete(tabId);
}

/** Flush events to storage */
async function flushEvents(tabId: number): Promise<void> {
  if (!monitoredBuffer.has(tabId) || monitoredBuffer.get(tabId)!.length === 0) return;
  const events = monitoredBuffer.get(tabId)!;
  monitoredBuffer.set(tabId, []);

  try {
    await storageRef!.local.set({
      [`events_${tabId}`]: events,
    });
  } catch (e) {
    console.warn('[X-Ray] Could not flush events to storage:', e);
  }
}

/** Insert events into buffer with dedup */
function insertEvent(tabId: number, event: MonitoredRequest): void {
  let events = monitoredBuffer.get(tabId) || [];
  // Simple dedup: skip if same API+url+timestamp within 2s
  const last = events[events.length - 1];
  if (last && last.api === event.api && last.url === event.url &&
    Math.abs(last.timestamp - event.timestamp) < 2000) {
    return; // Duplicate
  }
  events.push(event);
  monitoredBuffer.set(tabId, events);
}

// ---------------------------------------------------------------------------
// fetch() patching
// ---------------------------------------------------------------------------

function patchFetch(tabId: number) {
  if ((globalThis as any).__xray_fetch_patched__) return;
  (globalThis as any).__xray_fetch_patched__ = true;

  const originalFetch = fetch;

  (globalThis as any).fetch = function (input: RequestInfo, init?: RequestInit) {
    try {
      const request = typeof input === 'string' ? new Request(input, init || {}) : input;
      const url = new URL(request.url);

      // Skip if same-origin (reduces noise)
      if (url.hostname === (document as Document).location.hostname) {
        // Still call original, but don't monitor same-origin
        return originalFetch.call(this, input, init);
      }

      const event: MonitoredRequest = {
        id: `evt_f_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        api: 'fetch',
        method: request.method || 'GET',
        url: request.url,
        destinationHost: url.hostname,
        timestamp: Date.now(),
        sourcePage: document.title || document.location.href,
        resourceType: request.resourceType,
        correlatedWithSensitiveInput: false, // Set by content script if known
      };

      insertEvent(tabId, event);

      // Forward to background via message
      try {
        chrome.tabs.sendMessage(tabId, {
          kind: 'XRAY_NETWORK_EVENT',
          payload: event,
        }).catch(() => {/* tab may have been unloaded */});
      } catch (e) {
        // Maybe debugger / isolated world - log
      }

      return originalFetch.call(this, input, init);
    } catch (e) {
      // Fallback if patching fails
      return originalFetch.call(this, input, init);
    }
  };
}

// ---------------------------------------------------------------------------
// XMLHttpRequest patching
// ---------------------------------------------------------------------------

function patchXHR(tabId: number) {
  if ((globalThis as any).__xray_xhr_patched__) return;
  (globalThis as any).__xray_xhr_patched__ = true;

  const originalXHR = (globalThis as any).XMLHttpRequest;

  class XRayXHR extends originalXHR {
    originalOpen: typeof originalXHR.prototype.open;
    originalSend: typeof originalXHR.prototype.send;

    constructor() {
      super();
      this.originalOpen = this.open.bind(this);
      this.originalSend = this.send.bind(this);
    }

    open(method: string, url: string): void {
      // Store original and patch send
      const self = this;
      this.addEventListener('loadend', () => {
        try {
          const url = new URL(self.responseURL, document.location.href);
          // Skip same-origin
          if (url.hostname === (document as Document).location.hostname) {
            return;
          }

          const event: MonitoredRequest = {
            id: `evt_x_${Date.now()}_${Math.random().toString(36).slice(2)}`,
            api: 'xhr',
            method: self.method || 'GET',
            url: self.responseURL || url.toString(),
            destinationHost: url.hostname,
            timestamp: Date.now(),
            sourcePage: document.title || document.location.href,
            resourceType: '',
          };

          insertEvent(tabId, event);
          chrome.tabs.sendMessage(tabId, {
            kind: 'XRAY_NETWORK_EVENT',
            payload: event,
          }).catch(() => {/* tab may have been unloaded */});
        } catch (e) {
          console.warn('[X-Ray] XHR event processing error:', e);
        }
      }, { once: true });

      this.originalOpen(method, url);
    }

    send(data?: any): void {
      // Canary tracking: check if canary token was in the request body
      // (this is simplified - real detection needs content analysis)
    }
  }

  // Monkey-patch the prototype
  try {
    (globalThis as any).XMLHttpRequest = XRayXHR;
  } catch (e) {
    console.warn('[X-Ray] XHR patching encountered error:', e);
  }
}

// ---------------------------------------------------------------------------
// sendBeacon patching
// ---------------------------------------------------------------------------

function patchSendBeacon(tabId: number) {
  if ((globalThis as any).__xray_beacon_patched__) return;
  (globalThis as any).__xray_beacon_patched__ = true;

  const originalBeacon = (globalThis as any).navigator.sendBeacon;

  if (!originalBeacon) return;

  (globalThis as any).navigator.sendBeacon = function (url: string, data?: string | ArrayBuffer) {
    try {
      const parsedUrl = new URL(url);
      const destHost = parsedUrl.hostname;

      // Skip same-origin
      if (destHost === (document as Document).location.hostname) {
        return originalBeacon.call(navigator, url, data);
      }

      const event: MonitoredRequest = {
        id: `evt_b_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        api: 'sendBeacon',
        method: 'POST',
        url,
        destinationHost: destHost,
        timestamp: Date.now(),
        sourcePage: document.title || document.location.href,
        resourceType: 'beacon',
      };

      insertEvent(tabId, event);
      chrome.tabs.sendMessage(tabId, {
        kind: 'XRAY_NETWORK_EVENT',
        payload: event,
      }).catch(() => {/* tab may have been unloaded */});

      return originalBeacon.call(navigator, url, data);
    } catch (e) {
      return originalBeacon.call(navigator, url, data);
    }
  };
}

// ---------------------------------------------------------------------------
// WebSocket patching
// ---------------------------------------------------------------------------

function patchWebSocket(tabId: number) {
  if ((globalThis as any).__xray_ws_patched__) return;
  (globalThis as any).__xray_ws_patched__ = true;

  const originalWebSocket = (globalThis as any).WebSocket;

  if (!originalWebSocket) return;

  (globalThis as any).WebSocket = function (url: string | URL, protocols?: string) {
    try {
      const parsedUrl = typeof url === 'string' ? new URL(url) : url;
      const destHost = parsedUrl.hostname;

      // Skip same-origin
      if (destHost === (document as Document).location.hostname) {
        return new originalWebSocket(url, protocols);
      }

      const event: MonitoredRequest = {
        id: `evt_w_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        api: 'websocket',
        method: 'GET',
        url: url.toString(),
        destinationHost: destHost,
        timestamp: Date.now(),
        sourcePage: document.title || document.location.href,
        resourceType: 'websocket',
      };

      insertEvent(tabId, event);
      chrome.tabs.sendMessage(tabId, {
        kind: 'XRAY_NETWORK_EVENT',
        payload: event,
      }).catch(() => {/* tab may have been unloaded */});

      return new originalWebSocket(url, protocols);
    } catch (e) {
      return new originalWebSocket(url, protocols);
    }
  };
}

// ---------------------------------------------------------------------------
// Initialize monitoring for a tab
// ---------------------------------------------------------------------------

export function initMonitoring(tabId: number): void {
  try {
    patchFetch(tabId);
    patchXHR(tabId);
    patchSendBeacon(tabId);
    patchWebSocket(tabId);
    cleanupTab(tabId);
  } catch (e) {
    console.error('[X-Ray] Error initializing monitoring:', e);
  }
}

export function setStorageRef(storage: chrome.storage.Storage) {
  setStorage(storage);
}

/** Forcibly flush events when tab is about to close */
export function onTabUnload(tabId: number): void {
  cleanupTab(tabId);
  flushEvents(tabId);
}