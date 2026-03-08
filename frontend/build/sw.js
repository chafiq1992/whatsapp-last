// Bump this whenever caching logic changes to ensure clients pick up the new SW behavior.
const CACHE_VERSION = 'v8';
const RUNTIME_CACHE = `runtime-${CACHE_VERSION}`;
const STATIC_CACHE = `static-${CACHE_VERSION}`;

const STATIC_ASSETS = [
  // Intentionally avoid caching the HTML shell to prevent stale index referencing old asset hashes
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((key) => {
      if (!key.includes(CACHE_VERSION)) return caches.delete(key);
    }))).then(() => self.clients.claim())
  );
});

// Simple routing: cache-first for images/fonts; stale-while-revalidate for others; bypass APIs
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  const path = url.pathname;
  const hasRange = !!req.headers.get('range');
  const authHeader = req.headers.get('authorization') || req.headers.get('Authorization');

  // Skip non-GET, Range requests, or API-like endpoints entirely
  if (req.method !== 'GET') return;
  if (hasRange) return;
  // Skip non-http(s) schemes (e.g., chrome-extension:, blob:)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  // Always bypass requests that carry Authorization, or dynamic API routes that must be fresh
  if (authHeader) return;
  if (
    path.startsWith('/api') ||
    path.startsWith('/conversations') ||
    path.startsWith('/messages') ||
    path.startsWith('/admin') ||
    path.startsWith('/auth') ||
    path.startsWith('/ws') ||
    path.startsWith('/media/proxy') ||
    path.startsWith('/proxy-audio') ||
    path.startsWith('/proxy-media') ||
    path.startsWith('/link-preview')
  ) return;

  // Cache-first for image proxy endpoint to enable fast thumbnail loads and offline viewing
  if (path.startsWith('/proxy-image')) {
    event.respondWith((async () => {
      const cache = await caches.open(RUNTIME_CACHE);
      // Important: ignore Vary so <img> requests and fetch() requests share the same cached entry.
      const cached = await cache.match(req, { ignoreVary: true });
      if (cached) {
        // Best-effort refresh in background, but NEVER cache non-200 responses (e.g. 429 rate limit pages).
        event.waitUntil((async () => {
          try {
            const res = await fetch(req);
            if (res && res.ok) await cache.put(req, res.clone());
          } catch {}
        })());
        return cached;
      }
      const res = await fetch(req);
      if (res && res.ok) await cache.put(req, res.clone());
      return res;
    })());
    return;
  }

  // Always fetch a fresh HTML shell to avoid stale hashed asset references
  if (path === '/' || path.endsWith('/index.html')) {
    event.respondWith(
      fetch(req, { cache: 'no-store' })
        .then((res) => {
          // Keep an offline fallback copy without serving stale by default
          const copy = res.clone();
          caches.open(RUNTIME_CACHE).then((cache) => cache.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  // Images and fonts: cache-first
  if (/\/(images?|img|media)\//i.test(path) || /(\.png|\.jpg|\.jpeg|\.gif|\.webp|\.svg|\.ico|\.woff2?|\.ttf)$/i.test(path)) {
    event.respondWith(
      caches.match(req).then((cached) => cached || fetch(req).then((res) => {
        const copy = res.clone();
        if (res && res.ok) caches.open(RUNTIME_CACHE).then((cache) => cache.put(req, copy));
        return res;
      }))
    );
    return;
  }

  // Default: stale-while-revalidate for same-origin GET
  event.respondWith(
    caches.match(req).then((cached) => {
      const fetched = fetch(req).then((res) => {
        const copy = res.clone();
        if (res && res.ok) caches.open(RUNTIME_CACHE).then((cache) => cache.put(req, copy));
        return res;
      }).catch(() => cached);
      return cached || fetched;
    })
  );
});

// ---------------------------------------------------------------------------
// Background precache of thumbnails
// ---------------------------------------------------------------------------
// IMPORTANT: Agents can open large catalogs and trigger many PRECACHE_THUMBS messages quickly.
// If we start a new concurrency pool per message, we can easily flood /proxy-image and cause
// 429/503 storms + flickering images. Instead: maintain ONE global queue + ONE concurrency pool.

const PRECACHE_STATE = {
  queue: [],
  running: false,
  seen: new Set(),       // URLs we've queued/processed this session
  failUntil: new Map(),  // URL -> epoch ms until we try again
};

async function drainPrecacheQueue() {
  if (PRECACHE_STATE.running) return;
  PRECACHE_STATE.running = true;
  try {
    const cache = await caches.open(RUNTIME_CACHE);
    const CONCURRENCY = 6;
    const COOL_DOWN_MS = 60 * 1000;

    const worker = async () => {
      while (PRECACHE_STATE.queue.length) {
        const u = PRECACHE_STATE.queue.shift();
        if (!u) continue;
        try {
          const until = PRECACHE_STATE.failUntil.get(u) || 0;
          if (until > Date.now()) continue;

          const match = await cache.match(u, { ignoreVary: true });
          if (match) continue;

          const res = await fetch(u);
          if (res && res.ok) {
            await cache.put(u, res.clone());
          } else {
            // Don't spam retries when the backend or upstream is rate limiting / unavailable.
            if (res && (res.status === 429 || res.status >= 500)) {
              PRECACHE_STATE.failUntil.set(u, Date.now() + COOL_DOWN_MS);
            }
          }
        } catch {
          PRECACHE_STATE.failUntil.set(u, Date.now() + COOL_DOWN_MS);
        }
      }
    };

    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  } finally {
    PRECACHE_STATE.running = false;
    // If more items were queued while we were draining, schedule another pass.
    if (PRECACHE_STATE.queue.length) {
      setTimeout(() => { drainPrecacheQueue(); }, 0);
    }
  }
}

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'PRECACHE_THUMBS' && Array.isArray(data.urls)) {
    const urls = Array.from(new Set(data.urls.filter(Boolean)));
    // Cap memory growth; if a user keeps switching catalogs, don't leak forever.
    if (PRECACHE_STATE.seen.size > 10_000) {
      PRECACHE_STATE.seen.clear();
      PRECACHE_STATE.failUntil.clear();
    }
    for (const u of urls) {
      if (PRECACHE_STATE.seen.has(u)) continue;
      const until = PRECACHE_STATE.failUntil.get(u) || 0;
      if (until > Date.now()) continue;
      PRECACHE_STATE.seen.add(u);
      PRECACHE_STATE.queue.push(u);
    }
    event.waitUntil(drainPrecacheQueue());
  }
});


