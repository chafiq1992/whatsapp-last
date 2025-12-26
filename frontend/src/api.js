import axios from 'axios';

// Use .env, fallback to localhost for dev
const baseUrl =
  process.env.REACT_APP_API_BASE ||
  process.env.REACT_APP_API_URL || // Accept either for portability
  process.env.REACT_APP_BACKEND_URL ||
  "";

const api = axios.create({
  baseURL: baseUrl,
  // Use HttpOnly cookies for auth (access + refresh). This is safer than localStorage tokens.
  withCredentials: true,
});

function getStoredToken(key) {
  // Prefer sessionStorage (tab-scoped). Fall back to localStorage for embedded/3P-cookie-blocked contexts.
  // NOTE: localStorage tokens are less safe than HttpOnly cookies; we use this only as a fallback.
  try {
    const t = sessionStorage.getItem(key);
    if (t) return t;
  } catch {}
  try {
    const t = localStorage.getItem(key);
    if (t) return t;
  } catch {}
  return null;
}

function setStoredToken(key, value) {
  if (!value) return;
  try { sessionStorage.setItem(key, value); } catch {}
  try { localStorage.setItem(key, value); } catch {}
}

function clearStoredToken(key) {
  try { sessionStorage.removeItem(key); } catch {}
  try { localStorage.removeItem(key); } catch {}
}

function getWorkspace() {
  try {
    const w = (localStorage.getItem('workspace') || '').trim().toLowerCase();
    return w || 'irranova';
  } catch {
    return 'irranova';
  }
}

// Avoid stale caches for GETs and attach auth token
api.interceptors.request.use((config) => {
  try {
    // Workspace routing header (tenant selection)
    config.headers = {
      ...(config.headers || {}),
      'X-Workspace': getWorkspace(),
    };

    // Fallback: attach Authorization header from sessionStorage if present
    // (used only when cookies are blocked/dropped by the client).
    try {
      const t = getStoredToken('agent_access_token');
      if (t) {
        config.headers = {
          ...(config.headers || {}),
          Authorization: `Bearer ${t}`,
        };
      }
    } catch {}

    if ((config.method || 'get').toLowerCase() === 'get') {
      // Add cache-buster param
      const ts = Date.now();
      if (typeof config.url === 'string') {
        if (config.url.includes('?')) config.url += `&__ts=${ts}`; else config.url += `?__ts=${ts}`;
      }
      // And explicit no-cache headers
      config.headers = {
        ...(config.headers || {}),
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
      };
    }
  } catch {}
  return config;
});

let _refreshInFlight = null;

async function refreshSession() {
  // Prefer header-based refresh token fallback if present (for cookie-blocked clients).
  let rt = null;
  rt = getStoredToken('agent_refresh_token');
  if (rt) {
    const res = await api.post('/auth/refresh', null, { headers: { 'X-Refresh-Token': rt } });
    const at = res?.data?.access_token;
    const nrt = res?.data?.refresh_token;
    setStoredToken('agent_access_token', at);
    // Refresh token may not be returned (depends on backend config)
    if (nrt) setStoredToken('agent_refresh_token', nrt);
    return res;
  }
  // Cookie-based refresh (normal path)
  const res = await api.post('/auth/refresh');
  const at = res?.data?.access_token;
  const nrt = res?.data?.refresh_token;
  setStoredToken('agent_access_token', at);
  if (nrt) setStoredToken('agent_refresh_token', nrt);
  return res;
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    try {
      const status = error?.response?.status;
      const original = error?.config;
      const url = String(original?.url || '');
      const isAuthCall = url.includes('/auth/login') || url.includes('/auth/refresh');
      if (status === 401 && original && !original.__retried && !isAuthCall) {
        original.__retried = true;
        if (!_refreshInFlight) {
          _refreshInFlight = refreshSession().finally(() => { _refreshInFlight = null; });
        }
        try {
          await _refreshInFlight;
          return api(original);
        } catch (e) {
          // If refresh fails (e.g., cookies blocked), drop any header token and force re-login.
          clearStoredToken('agent_access_token');
          clearStoredToken('agent_refresh_token');
          try { window.location.replace('/login'); } catch {}
          throw e;
        }
      }
    } catch {}
    return Promise.reject(error);
  },
);

// expose axios utility helpers on the instance
api.isCancel = axios.isCancel;

export default api;
