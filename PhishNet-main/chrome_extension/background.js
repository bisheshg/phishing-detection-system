/* ── background.js — PhishNet service worker ─────────────
   MV3 service worker.
   - Watches tab navigations and activations
   - Scans URLs via the Express backend (port 8800)
   - Reads the access_token from Chrome cookie store and
     passes it as Authorization: Bearer (bypasses SameSite=Lax)
   - Updates the action badge: ! red / ✓ green / … scanning
   - Caches results in chrome.storage.session
──────────────────────────────────────────────────────── */

const API       = 'http://localhost:8800/api';
const TOKEN_KEY = 'phishnet_token';
const CACHE_KEY = 'phishnet_cache';
const CACHE_TTL = 5 * 60 * 1000; // 5 min

// In-memory token cache — refreshed from storage.local when needed
let cachedToken = null;

/* ── Badge helpers ────────────────────────────────────── */
function setBadge(tabId, verdict) {
  if (verdict === 'Phishing') {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
  } else if (verdict === 'Legitimate') {
    chrome.action.setBadgeText({ tabId, text: '✓' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#16a34a' });
  } else if (verdict === 'scanning') {
    chrome.action.setBadgeText({ tabId, text: '…' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#4338ca' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

/* ── Token from chrome.storage.local ─────────────────── */
async function getToken() {
  if (cachedToken) return cachedToken;
  try {
    const s = await chrome.storage.local.get(TOKEN_KEY);
    cachedToken = s[TOKEN_KEY] || null;
    return cachedToken;
  } catch {
    return null;
  }
}

function authHeaders(token, json = false) {
  const h = {};
  if (json) h['Content-Type'] = 'application/json';
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

/* ── Cache helpers ────────────────────────────────────── */
async function getCached(url) {
  try {
    const store = await chrome.storage.session.get(CACHE_KEY);
    const cache = store[CACHE_KEY] || {};
    const entry = cache[url];
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL) return null;
    return entry.data;
  } catch {
    return null;
  }
}

async function setCached(url, data) {
  try {
    const store = await chrome.storage.session.get(CACHE_KEY);
    const cache = store[CACHE_KEY] || {};
    cache[url] = { data, ts: Date.now() };
    const keys = Object.keys(cache);
    if (keys.length > 80) {
      keys.sort((a, b) => cache[a].ts - cache[b].ts)
          .slice(0, keys.length - 80)
          .forEach(k => delete cache[k]);
    }
    await chrome.storage.session.set({ [CACHE_KEY]: cache });
  } catch { /* non-fatal */ }
}

/* ── Scan a URL and update badge ─────────────────────── */
async function scanAndBadge(tabId, url) {
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    setBadge(tabId, 'clear');
    return;
  }

  // Check cache first — instant badge update
  const cached = await getCached(url);
  if (cached) {
    setBadge(tabId, cached.prediction);
    return;
  }

  // Show "scanning" badge
  setBadge(tabId, 'scanning');

  // Read token
  const token = await getToken();
  if (!token) {
    setBadge(tabId, 'clear');
    return;
  }

  try {
    const res = await fetch(`${API}/phishing/analyze`, {
      method: 'POST',
      headers: authHeaders(token, true),
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(20000),
    });

    if (!res.ok) {
      setBadge(tabId, 'clear');
      return;
    }

    const result = await res.json();
    if (result.success && result.data) {
      await setCached(url, result.data);
      setBadge(tabId, result.data.prediction);
    } else {
      setBadge(tabId, 'clear');
    }
  } catch {
    setBadge(tabId, 'clear');
  }
}

/* ── Tab event listeners ─────────────────────────────── */

// Page finished loading in the active tab
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active) {
    scanAndBadge(tabId, tab.url);
  }
});

// User switched to a different tab — show cached badge instantly
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url) return;

    const cached = await getCached(tab.url);
    if (cached) {
      setBadge(tabId, cached.prediction);
    } else if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      scanAndBadge(tabId, tab.url);
    } else {
      setBadge(tabId, 'clear');
    }
  } catch { /* tab may no longer exist */ }
});

/* ── Messages from popup ─────────────────────────────── */
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SCAN_RESULT' && msg.url && msg.data) {
    // Popup finished a scan — update cache and badge
    setCached(msg.url, msg.data);
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (tab) setBadge(tab.id, msg.data.prediction);
    });
  } else if (msg.type === 'TOKEN_UPDATED' && msg.token) {
    // Popup stored a new token — refresh in-memory cache
    cachedToken = msg.token;
  } else if (msg.type === 'TOKEN_CLEARED') {
    // Popup signed out — clear in-memory token
    cachedToken = null;
  }
});
