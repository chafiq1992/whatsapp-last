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

// Avoid stale caches for GETs and attach auth token
api.interceptors.request.use((config) => {
  try {
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
          _refreshInFlight = api.post('/auth/refresh').finally(() => { _refreshInFlight = null; });
        }
        await _refreshInFlight;
        return api(original);
      }
    } catch {}
    return Promise.reject(error);
  },
);

// expose axios utility helpers on the instance
api.isCancel = axios.isCancel;

export default api;
