/* ── popup.js — PhishNet Chrome Extension v2 ────────────── */

const API     = 'http://localhost:8800/api';
const WEB_APP = 'http://localhost:3000';

// chrome.storage.local keys
const TOKEN_KEY = 'phishnet_token';
const USER_KEY  = 'phishnet_user';
const CACHE_KEY = 'phishnet_cache';
const CACHE_TTL = 5 * 60 * 1000; // 5 min

/* ── DOM refs ─────────────────────────────────────────── */
const $ = id => document.getElementById(id);
const urlText      = $('urlText');
const stateLoading = $('stateLoading');
const stateLogin   = $('stateLogin');
const stateNA      = $('stateNA');
const stateError   = $('stateError');
const stateResult  = $('stateResult');
const loginEmail   = $('loginEmail');
const loginPassword = $('loginPassword');
const loginError   = $('loginError');
const errorMsg     = $('errorMsg');
const verdictCard  = $('verdictCard');
const verdictIcon  = $('verdictIcon');
const verdictLabel = $('verdictLabel');
const verdictSub   = $('verdictSub');
const statConf     = $('statConfidence');
const statRisk     = $('statRisk');
const statSrc      = $('statSource');
const confBarFill  = $('confBarFill');
const confBarPct   = $('confBarPct');
const violBox      = $('violationsBox');
const violList     = $('violationsList');
const footerUser   = $('footerUser');
const footerDash   = $('footerDashboard');
const btnSignIn    = $('btnSignIn');
const btnOpenApp   = $('btnOpenApp');
const btnRetry     = $('btnRetry');
const btnRescan    = $('btnRescan');
const btnHistory   = $('btnHistory');
const btnSignOut   = $('btnSignOut');

/* ── Helpers ──────────────────────────────────────────── */
function showOnly(el) {
  [stateLoading, stateLogin, stateNA, stateError, stateResult]
    .forEach(s => { s.style.display = s === el ? '' : 'none'; });
}

function isScannable(url) {
  return url && (url.startsWith('http://') || url.startsWith('https://'));
}

function sourceLabel(src) {
  return { blacklist: 'Blacklist', rule_engine: 'Rule Engine', ml_ensemble: 'ML Model', trusted: 'Trusted' }[src] || src || '—';
}

/* ── Token storage (chrome.storage.local) ─────────────
   Stored here after a successful login so the extension
   works independently — no cookie/SameSite issues.
──────────────────────────────────────────────────────── */
async function getToken() {
  const s = await chrome.storage.local.get(TOKEN_KEY);
  return s[TOKEN_KEY] || null;
}

async function saveAuth(token, user) {
  await chrome.storage.local.set({ [TOKEN_KEY]: token, [USER_KEY]: user });
  // Tell background service worker so its badge scans also use this token
  chrome.runtime.sendMessage({ type: 'TOKEN_UPDATED', token }).catch(() => {});
}

async function clearAuth() {
  await chrome.storage.local.remove([TOKEN_KEY, USER_KEY]);
  chrome.runtime.sendMessage({ type: 'TOKEN_CLEARED' }).catch(() => {});
}

function authHeader(token) {
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

/* ── Cache ────────────────────────────────────────────── */
async function getCached(url) {
  const s = await chrome.storage.local.get(CACHE_KEY);
  const cache = s[CACHE_KEY] || {};
  const entry = cache[url];
  if (!entry || Date.now() - entry.ts > CACHE_TTL) return null;
  return entry.data;
}

async function setCached(url, data) {
  const s = await chrome.storage.local.get(CACHE_KEY);
  const cache = s[CACHE_KEY] || {};
  cache[url] = { data, ts: Date.now() };
  const keys = Object.keys(cache);
  if (keys.length > 60) {
    keys.sort((a, b) => cache[a].ts - cache[b].ts).slice(0, keys.length - 60).forEach(k => delete cache[k]);
  }
  await chrome.storage.local.set({ [CACHE_KEY]: cache });
}

async function clearCached(url) {
  const s = await chrome.storage.local.get(CACHE_KEY);
  const cache = s[CACHE_KEY] || {};
  delete cache[url];
  await chrome.storage.local.set({ [CACHE_KEY]: cache });
}

/* ── API calls ────────────────────────────────────────── */
async function verifyToken(token) {
  const res = await fetch(`${API}/auth/user`, {
    headers: authHeader(token),
  });
  if (!res.ok) return null;
  const data = await res.json();
  // endpoint returns { status: true/false, user: {...} }
  return data.status ? data.user : null;
}

async function scanUrl(url, token) {
  const res = await fetch(`${API}/phishing/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeader(token) },
    body: JSON.stringify({ url }),
  });
  if (res.status === 401 || res.status === 403) throw new Error('AUTH');
  if (res.status === 429) throw new Error('RATE_LIMIT');
  if (!res.ok) throw new Error(`HTTP_${res.status}`);
  return res.json();
}

/* ── Render result ────────────────────────────────────── */
function renderResult(data) {
  const isPhishing  = data.prediction === 'Phishing';
  const isBlacklist = data.detection_source === 'blacklist';
  const conf = data.confidence ?? 0;
  const risk = data.risk_level || data.riskLevel || '—';

  verdictCard.className = 'verdict-card ' + (isPhishing ? (isBlacklist ? 'blacklist' : 'phishing') : 'legitimate');
  verdictIcon.textContent  = isPhishing ? (isBlacklist ? '🚫' : '⚠️') : '✅';
  verdictLabel.textContent = isPhishing ? (isBlacklist ? 'Blacklisted Site' : 'Phishing Detected') : 'Looks Legitimate';
  verdictSub.textContent   = isPhishing ? 'Do not enter credentials on this site.' : 'No phishing signals detected.';

  statConf.textContent = conf ? `${conf}%` : '—';
  statRisk.textContent = risk;
  statSrc.textContent  = sourceLabel(data.detection_source);

  const pct = Math.min(Math.max(conf, 0), 100);
  confBarFill.style.width = `${pct}%`;
  confBarFill.className   = 'conf-bar-fill ' + (isPhishing ? 'danger' : 'safe');
  confBarPct.textContent  = conf ? `${conf}%` : '';

  const violations = data.rule_violations || data.violations || [];
  if (violations.length > 0) {
    violBox.style.display = '';
    violList.innerHTML = '';
    violations.slice(0, 5).forEach(v => {
      const li = document.createElement('li');
      li.textContent = typeof v === 'string' ? v : (v.message || v.rule || String(v));
      violList.appendChild(li);
    });
  } else {
    violBox.style.display = 'none';
  }

  showOnly(stateResult);
}

/* ── Main flow ────────────────────────────────────────── */
let currentUrl = '';

async function run() {
  showOnly(stateLoading);

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || '';
  currentUrl = url;
  urlText.textContent = url.length > 55 ? url.slice(0, 55) + '…' : (url || '—');

  if (!isScannable(url)) { showOnly(stateNA); return; }

  // Check stored token
  const token = await getToken();
  if (!token) { showOnly(stateLogin); return; }

  // Verify token is still valid
  let user = null;
  try { user = await verifyToken(token); } catch { /* network error — still try scan */ }

  if (!user) {
    // Token expired or invalid — clear it and show login
    await clearAuth();
    showOnly(stateLogin);
    return;
  }

  // Show user info + sign-out button
  footerUser.textContent = user.name || user.email || 'Logged in';
  btnSignOut.style.display = '';

  // Check cache
  const cached = await getCached(url);
  if (cached) { renderResult(cached); return; }

  // Scan the URL
  try {
    const result = await scanUrl(url, token);
    if (result.success && result.data) {
      await setCached(url, result.data);
      chrome.runtime.sendMessage({ type: 'SCAN_RESULT', url, data: result.data }).catch(() => {});
      renderResult(result.data);
    } else {
      throw new Error(result.message || 'Unexpected response');
    }
  } catch (err) {
    if (err.message === 'AUTH') {
      await clearAuth();
      showOnly(stateLogin);
    } else if (err.message === 'RATE_LIMIT') {
      errorMsg.textContent = 'Daily scan limit reached. Upgrade to Premium for more scans.';
      showOnly(stateError);
    } else {
      errorMsg.textContent = 'Could not reach the PhishNet backend (port 8800). Make sure it is running.';
      showOnly(stateError);
    }
  }
}

/* ── Login handler ────────────────────────────────────── */
async function handleLogin() {
  const email    = loginEmail.value.trim();
  const password = loginPassword.value;
  loginError.textContent = '';

  if (!email || !password) {
    loginError.textContent = 'Please enter your email and password.';
    return;
  }

  btnSignIn.disabled     = true;
  btnSignIn.textContent  = 'Signing in…';

  try {
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      loginError.textContent = data.message || data.error || 'Login failed. Check your credentials.';
      return;
    }

    // Login response includes _ext_token in the body
    const token = data._ext_token;
    if (!token) {
      loginError.textContent = 'Login succeeded but no token received. Please restart the backend.';
      return;
    }

    // Store token + user info
    await saveAuth(token, { name: data.name, email: data.email });

    // Clear the form
    loginEmail.value    = '';
    loginPassword.value = '';

    // Run the scan flow
    await run();

  } catch {
    loginError.textContent = 'Cannot reach PhishNet backend on port 8800.';
  } finally {
    btnSignIn.disabled    = false;
    btnSignIn.textContent = 'Sign In';
  }
}

/* ── Button listeners ─────────────────────────────────── */
btnSignIn.addEventListener('click', handleLogin);

loginPassword.addEventListener('keydown', e => {
  if (e.key === 'Enter') handleLogin();
});

btnOpenApp.addEventListener('click', () => {
  chrome.tabs.create({ url: WEB_APP + '/login' });
});

btnRetry.addEventListener('click', () => run());

btnRescan.addEventListener('click', async () => {
  await clearCached(currentUrl);
  run();
});

btnHistory.addEventListener('click', () => {
  chrome.tabs.create({ url: WEB_APP + '/scan-history' });
});

footerDash.addEventListener('click', e => {
  e.preventDefault();
  chrome.tabs.create({ url: WEB_APP + '/dashboard' });
});

btnSignOut.addEventListener('click', async () => {
  await clearAuth();
  btnSignOut.style.display = 'none';
  footerUser.textContent   = '';
  showOnly(stateLogin);
});

/* ── Boot ─────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  run().catch(err => {
    errorMsg.textContent = `Unexpected error: ${err.message}`;
    showOnly(stateError);
  });
});
