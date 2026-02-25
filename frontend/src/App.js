// /frontend/src/App.jsx
import React, { useEffect, useState, useRef, Suspense } from 'react';
import ChatList from './ChatList';
import InternalChannelsBar from './InternalChannelsBar';
import MiniSidebar from './MiniSidebar';
import AgentHeaderBar from './AgentHeaderBar';
import ChatWindow from './ChatWindow';
import api from './api';
import { loadConversations, saveConversations } from './chatStorage';
import { AudioProvider } from './AudioManager';
import GlobalAudioBar from './GlobalAudioBar';
// Lazy load heavy panels (must be declared after all import declarations)
const ShopifyIntegrationsPanel = React.lazy(() => import('./ShopifyIntegrationsPanel'));
const Login = React.lazy(() => import('./Login'));

// Read API base from env for production/dev compatibility
// Default to relative paths if not provided
const API_BASE = process.env.REACT_APP_API_BASE || "";

// Normalize timestamps across types and formats; treat naive ISO as UTC
const toMsNormalized = (t) => {
  if (!t) return 0;
  if (t instanceof Date) return t.getTime();
  if (typeof t === 'number') return t;
  const s = String(t);
  if (/^\d+$/.test(s)) return Number(s) * (s.length <= 10 ? 1000 : 1);
  if (s.includes('T') && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) {
    const ms = Date.parse(s + 'Z');
    if (!Number.isNaN(ms)) return ms;
  }
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? 0 : ms;
};

export default function App() {
  const [workspace, setWorkspace] = useState(() => {
    try {
      return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova';
    } catch {
      return 'irranova';
    }
  });
  const [products, setProducts] = useState([]);
  const [catalogProducts, setCatalogProducts] = useState({});
  const [conversations, setConversations] = useState([]);
  const CONV_PAGE_LIMIT = 200;
  const [convOffset, setConvOffset] = useState(0);
  const [convHasMore, setConvHasMore] = useState(true);
  const [convLoadingMore, setConvLoadingMore] = useState(false);
  const [activeUser, setActiveUser] = useState(null);
  const [currentAgent, setCurrentAgent] = useState("");
  const [agentInboxMode, setAgentInboxMode] = useState(false);
  const [myAssignedOnly, setMyAssignedOnly] = useState(false);
  const [adminWsConnected, setAdminWsConnected] = useState(false);
  const [showArchive, setShowArchive] = useState(false);
  const [showInternalPanel, setShowInternalPanel] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loadingConversations, setLoadingConversations] = useState(false);
  const [authReady, setAuthReady] = useState(false);
  const activeUserRef = useRef(activeUser);
  const convFetchInFlightRef = useRef(null);
  const convMoreInFlightRef = useRef(null);

  const isLoginPath = typeof window !== 'undefined' && window.location && window.location.pathname === '/login';

  // WebSocket for chat and a separate one for admin updates
  const wsRef = useRef(null);
  const adminWsRef = useRef(null);
  const convPollRef = useRef(null);
  const adminPingRef = useRef(null);

  useEffect(() => {
    activeUserRef.current = activeUser;
  }, [activeUser]);

  // No version banner; backend serves fresh JS/CSS with no-cache headers

  // Compute a root font scale to preserve layout while making UI elements smaller
  useEffect(() => {
    const updateScale = () => {
      try {
        const baseWidth = 1200; // design reference width
        const baseHeight = 800; // design reference height
        const scaleW = window.innerWidth / baseWidth;
        const scaleH = window.innerHeight / baseHeight;
        // Keep within sensible bounds to maintain usability
        const scale = Math.min(1, Math.max(0.8, Math.min(scaleW, scaleH)));
        const baseFontPx = 16;
        document.documentElement.style.setProperty('--app-font-size', `${baseFontPx * scale}px`);
      } catch {}
    };
    updateScale();
    window.addEventListener('resize', updateScale);
    return () => window.removeEventListener('resize', updateScale);
  }, []);

  // Reflect latest message previews from ChatWindow globally so ChatList stays in sync
  useEffect(() => {
    const handler = (ev) => {
      const d = ev.detail || {};
      if (!d.user_id) return;
      setConversations((prev) => {
        const list = Array.isArray(prev) ? [...prev] : [];
        const idx = list.findIndex((c) => c.user_id === d.user_id);
        const nowIso = new Date().toISOString();
        const incomingIso = d.last_message_time || nowIso;
        const incomingMs = toMsNormalized(incomingIso);
        if (idx === -1) {
          const created = {
            user_id: d.user_id,
            name: d.name || d.user_id,
            last_message: d.last_message || '',
            last_message_type: d.last_message_type || 'text',
            last_message_time: incomingIso,
            last_message_from_me: typeof d.last_message_from_me === 'boolean' ? d.last_message_from_me : undefined,
            last_message_status: d.last_message_status,
            unread_count: activeUserRef.current?.user_id === d.user_id ? 0 : 1,
            tags: [],
          };
          return [created, ...list];
        }
        const updated = { ...list[idx] };
        const prevMs = toMsNormalized(updated.last_message_time || 0);
        const isNewer = incomingMs > prevMs;
        const isSame = incomingMs === prevMs;
        const sameContent = (
          (typeof d.last_message === 'string' ? d.last_message : '') === (typeof updated.last_message === 'string' ? updated.last_message : '') &&
          (d.last_message_type || '') === (updated.last_message_type || '') &&
          (typeof updated.last_message_from_me === 'boolean' ? updated.last_message_from_me : false)
        );

        // Only update preview content/from_me when the incoming event is newer
        if (isNewer) {
          if (d.last_message_type) updated.last_message_type = d.last_message_type;
          if (typeof d.last_message === 'string') updated.last_message = d.last_message;
          if (typeof d.last_message_from_me === 'boolean') updated.last_message_from_me = d.last_message_from_me;
          if (typeof d.last_message_status === 'string') updated.last_message_status = d.last_message_status;
          updated.last_message_time = incomingIso;
        } else {
          const rank = (s) => ({ sending: 0, sent: 1, delivered: 2, read: 3, failed: 99 }[s] ?? -1);
          // For same-timestamp updates, only lift delivery status if it improves
          if (isSame && typeof d.last_message_status === 'string' && updated.last_message_from_me) {
            const curr = updated.last_message_status;
            const next = d.last_message_status;
            if (!curr || rank(next) >= rank(curr)) updated.last_message_status = next;
          }
          // If incoming appears older but refers to the same message from me, still allow status upgrades
          if (!isNewer && !isSame && sameContent && typeof d.last_message_status === 'string') {
            const curr = updated.last_message_status;
            const next = d.last_message_status;
            if (!curr || rank(next) >= rank(curr)) updated.last_message_status = next;
          }
          // Keep the newer timestamp to maintain ordering; do not downgrade preview fields
          updated.last_message_time = new Date(Math.max(prevMs, incomingMs)).toISOString();
        }
        if (activeUserRef.current?.user_id === d.user_id) updated.unread_count = 0;
        const without = list.filter((_, i) => i !== idx);
        return [updated, ...without];
      });
    };
    window.addEventListener('conversation-preview', handler);
    return () => window.removeEventListener('conversation-preview', handler);
  }, []);

  // Clear unread count in chat list when opening a conversation
  useEffect(() => {
    if (!activeUser?.user_id) return;
    setConversations(prev => prev.map(c => c.user_id === activeUser.user_id ? { ...c, unread_count: 0 } : c));
  }, [activeUser?.user_id]);

  // Fetch all conversations for chat list
  const fetchConversations = async ({ showSpinner = false } = {}) => {
    // Avoid overlapping fetches (helps prevent 504s under load + UI flicker)
    if (convFetchInFlightRef.current) return convFetchInFlightRef.current;
    // Backoff on transient 503s so we don't stampede the backend during DB slowness
    if (!fetchConversations._backoff) fetchConversations._backoff = { until: 0, ms: 0 };
    try {
      const now = Date.now();
      if (fetchConversations._backoff.until && now < fetchConversations._backoff.until) {
        return Promise.resolve();
      }
    } catch {}
    const p = (async () => {
      try {
        if (showSpinner) setLoadingConversations(true);
        // Keep the initial inbox fetch light; server defaults are also capped.
        const res = await api.get(`${API_BASE}/conversations?limit=${CONV_PAGE_LIMIT}&offset=0`);
        const data = res?.data;
        if (Array.isArray(data)) {
          setConversations(data);
          setConvOffset(data.length);
          setConvHasMore(data.length >= CONV_PAGE_LIMIT);
          // Best-effort cache; don't block UI on IndexedDB
          try { saveConversations(data); } catch {}
        } else {
          // Unexpected payload shape: fall back to cached list
          const cached = await loadConversations();
          if (cached.length > 0) {
            setConversations(cached);
            setConvOffset(cached.length);
            setConvHasMore(cached.length >= CONV_PAGE_LIMIT);
          }
        }
        // Reset backoff on success
        try { fetchConversations._backoff = { until: 0, ms: 0 }; } catch {}
      } catch (err) {
        console.error('Failed to fetch conversations:', err);
        // If backend is temporarily busy, back off progressively (max ~30s).
        try {
          const status = err?.response?.status;
          if (status === 503) {
            const prev = fetchConversations._backoff?.ms || 0;
            const next = Math.min(30000, prev ? Math.round(prev * 1.8) : 4000);
            fetchConversations._backoff = { ms: next, until: Date.now() + next };
          }
        } catch {}
        const cached = await loadConversations();
        if (cached.length > 0) {
          setConversations(cached);
          setConvOffset(cached.length);
          setConvHasMore(cached.length >= CONV_PAGE_LIMIT);
        }
      } finally {
        convFetchInFlightRef.current = null;
        // Always clear spinner if it was shown
        if (showSpinner) setLoadingConversations(false);
      }
    })();
    convFetchInFlightRef.current = p;
    return p;
  };

  // Load additional/older conversations for the left chat list (infinite scroll)
  const loadMoreConversations = async () => {
    if (convLoadingMore || !convHasMore) return;
    if (convMoreInFlightRef.current) return convMoreInFlightRef.current;
    const p = (async () => {
      setConvLoadingMore(true);
      try {
        const nextOffset = convOffset;
        const res = await api.get(`${API_BASE}/conversations?limit=${CONV_PAGE_LIMIT}&offset=${nextOffset}`);
        const page = Array.isArray(res?.data) ? res.data : [];
        if (page.length === 0) {
          setConvHasMore(false);
          return;
        }
        setConversations((prev) => {
          const seen = new Set((prev || []).map((c) => c?.user_id));
          const merged = [...(prev || [])];
          for (const c of page) {
            if (!c?.user_id) continue;
            if (seen.has(c.user_id)) continue;
            merged.push(c);
            seen.add(c.user_id);
          }
          return merged;
        });
        setConvOffset((o) => o + page.length);
        setConvHasMore(page.length >= CONV_PAGE_LIMIT);
      } catch (e) {
        // Keep hasMore as-is; user can retry by scrolling again
      } finally {
        setConvLoadingMore(false);
      }
    })().finally(() => {
      convMoreInFlightRef.current = null;
    });
    convMoreInFlightRef.current = p;
    return p;
  };

  // Fetch ALL products in catalog and build a lookup for order message rendering
  const fetchCatalogProducts = async () => {
    try {
      const res = await api.get(`${API_BASE}/catalog-all-products`);
      const allProducts = res.data || [];

      // Only keep in-stock items
      const inStockProducts = allProducts.filter(p => Number(p.available_quantity) > 0);

      // Build the lookup only for in-stock products
      const lookup = {};
      inStockProducts.forEach(prod => {
        lookup[String(prod.retailer_id)] = {
          name: prod.name,
          image: prod.images?.[0]?.url,
          price: prod.price,
        };
      });

      setCatalogProducts(lookup);
      setProducts(inStockProducts);
    } catch (err) {
      setCatalogProducts({});
      console.error('Failed to fetch catalog products:', err);
    }
  };

  // Load conversations/products after auth is ready
  useEffect(() => {
    if (!authReady) return;
    if (isLoginPath) return;
    try { localStorage.setItem('workspace', String(workspace || 'irranova')); } catch {}
    // Prevent any cross-workspace UI leakage while the new workspace loads.
    setActiveUser(null);
    setConversations([]);
    setConvOffset(0);
    setConvHasMore(true);
    setConvLoadingMore(false);
    setCatalogProducts({});
    setProducts([]);
    loadConversations().then(cached => {
      if (cached.length > 0) {
        setConversations(cached);
      }
    });
    fetchConversations({ showSpinner: true });
    fetchCatalogProducts();
    // You can remove the interval now if using WebSocket for chat!
    // const interval = setInterval(() => {
    //   fetchConversations();
    //   fetchCatalogProducts();
    // }, 5000);
    // return () => clearInterval(interval);
  }, [authReady, isLoginPath, workspace]);

  // Keep conversations fresh even if WebSocket messages are missed (multi-instance without Redis, tab sleep, brief disconnects).
  // Strategy:
  // - Whenever the admin WS connects, do an immediate sync.
  // - When disconnected, poll periodically as a safety net.
  // - When tab becomes visible again, do an immediate sync.
  useEffect(() => {
    if (!authReady) return;
    if (isLoginPath) return;

    const clearPoll = () => {
      try { if (convPollRef.current) clearInterval(convPollRef.current); } catch {}
      convPollRef.current = null;
    };
    const startPoll = () => {
      if (convPollRef.current) return;
      // Keep this light; backend also caches aggressively and we use cache-buster headers.
      convPollRef.current = setInterval(() => {
        try { fetchConversations({ showSpinner: false }); } catch {}
      }, 15000);
    };

    if (adminWsConnected) {
      clearPoll();
      // Catch-up sync on connect (covers missed messages during reconnect)
      try { fetchConversations({ showSpinner: false }); } catch {}
    } else {
      startPoll();
    }

    const onVis = () => {
      try {
        if (document.visibilityState === 'visible') fetchConversations({ showSpinner: false });
      } catch {}
    };
    try { document.addEventListener('visibilitychange', onVis); } catch {}

    return () => {
      clearPoll();
      try { document.removeEventListener('visibilitychange', onVis); } catch {}
    };
  }, [authReady, isLoginPath, adminWsConnected]);

  // Read agent/channel from URL hash for deep links: #agent=alice&assigned=1 | #dm=alice | #team=sales
  useEffect(() => {
    const applyFromHash = () => {
      try {
        const raw = window.location.hash || '';
        const h = raw.startsWith('#') ? raw.slice(1) : raw;
        const params = new URLSearchParams(h);
        const agent = params.get('agent');
        const assigned = params.get('assigned');
        const dm = params.get('dm');
        const team = params.get('team');

        if (agent) {
          setCurrentAgent(agent);
          setAgentInboxMode(true);
        } else {
          setAgentInboxMode(false);
        }
        if (assigned != null) setMyAssignedOnly(assigned === '1' || assigned === 'true');
        if (dm) {
          setActiveUser({ user_id: `dm:${dm}`, name: `@${dm}` });
        } else if (team) {
          setActiveUser({ user_id: `team:${team}`, name: `#${team}` });
        }
      } catch {}
    };
    applyFromHash();
    window.addEventListener('hashchange', applyFromHash);
    return () => window.removeEventListener('hashchange', applyFromHash);
  }, []);

  // Hydrate currentAgent from localStorage if not set via hash
  useEffect(() => {
    try {
      if (!currentAgent) {
        const saved = localStorage.getItem('agent_username');
        if (saved) setCurrentAgent(saved);
      }
      const savedAdmin = localStorage.getItem('agent_is_admin');
      if (savedAdmin != null) setIsAdmin(savedAdmin === '1' || savedAdmin === 'true');
    } catch {}
  }, []);

  // Validate session with backend and hydrate admin flag
  useEffect(() => {
    if (isLoginPath) {
      // Don't hit /auth/me from the login page (prevents 401 loops/flicker)
      setAuthReady(true);
      return;
    }
    (async () => {
      try {
        const res = await api.get('/auth/me');
        const u = res?.data?.username;
        const a = !!res?.data?.is_admin;
        if (u && !currentAgent) setCurrentAgent(u);
        setIsAdmin(a);
        try { localStorage.setItem('agent_is_admin', a ? '1' : '0'); } catch {}
        setAuthReady(true);
      } catch (e) {
        // Not logged in → go to login screen
        try {
          const status = e?.response?.status;
          if (status === 401) {
            window.location.replace('/login');
            return;
          }
        } catch {}
        setAuthReady(true);
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto logout after inactivity (30 minutes).
  // This is a client-side safety net; the backend also enforces inactivity expiry.
  useEffect(() => {
    if (!authReady) return;
    if (isLoginPath) return;

    const INACT_MS = 30 * 60 * 1000;
    let timer = null;

    const doLogout = async () => {
      try { await api.post('/auth/logout'); } catch {}
      try { sessionStorage.removeItem('agent_access_token'); } catch {}
      try { sessionStorage.removeItem('agent_refresh_token'); } catch {}
      try { localStorage.removeItem('agent_access_token'); } catch {}
      try { localStorage.removeItem('agent_refresh_token'); } catch {}
      try { localStorage.removeItem('agent_is_admin'); } catch {}
      try { window.location.replace('/login'); } catch {}
    };

    const reset = () => {
      try { if (timer) clearTimeout(timer); } catch {}
      timer = setTimeout(doLogout, INACT_MS);
    };

    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((ev) => {
      try { window.addEventListener(ev, reset, { passive: true }); } catch {}
    });
    try { document.addEventListener('visibilitychange', reset); } catch {}
    reset();

    return () => {
      try { if (timer) clearTimeout(timer); } catch {}
      events.forEach((ev) => {
        try { window.removeEventListener(ev, reset); } catch {}
      });
      try { document.removeEventListener('visibilitychange', reset); } catch {}
    };
  }, [authReady, isLoginPath]);

  // Open a persistent WebSocket for admin notifications (with reconnection)
  useEffect(() => {
    if (!authReady) return;
    if (isLoginPath) return;
    let retry = 0;
    let timer = null;
    const wsBase =
      process.env.REACT_APP_WS_URL ||
      `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/`;

    const connectAdmin = () => {
      const qs = new URLSearchParams();
      try {
        const t = sessionStorage.getItem('agent_access_token') || localStorage.getItem('agent_access_token');
        if (t) qs.set('token', t);
      } catch {}
      qs.set('workspace', String(workspace || 'irranova'));
      const ws = new WebSocket(`${wsBase}admin?${qs.toString()}`);
      adminWsRef.current = ws;
      ws.addEventListener('open', () => {
        retry = 0;
        setAdminWsConnected(true);
        try { ws.send(JSON.stringify({ type: 'ping', ts: Date.now() })); } catch {}
        // Keepalive to prevent idle timeouts on proxies/load balancers
        try {
          if (adminPingRef.current) clearInterval(adminPingRef.current);
          adminPingRef.current = setInterval(() => {
            try { ws.readyState === 1 && ws.send(JSON.stringify({ type: 'ping', ts: Date.now() })); } catch {}
          }, 25000);
        } catch {}
      });
      ws.addEventListener('close', () => {
        setAdminWsConnected(false);
        try { if (adminPingRef.current) clearInterval(adminPingRef.current); } catch {}
        adminPingRef.current = null;
        const delay = Math.min(30000, 1000 * Math.pow(2, retry++)) + Math.floor(Math.random() * 500);
        timer = setTimeout(connectAdmin, delay);
      });
      ws.addEventListener('error', () => {
        setAdminWsConnected(false);
        try { if (adminPingRef.current) clearInterval(adminPingRef.current); } catch {}
        adminPingRef.current = null;
        try { ws.close(); } catch {}
      });
      ws.addEventListener('message', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.type === 'pong') return;
          // Hard guard: never apply WS events from a different workspace.
          // This prevents brief "flash" of cross-workspace messages during routing / reconnect edges.
          try {
            // Prefer top-level workspace; fall back to payload workspace (common for message_* events).
            const evWs = String(data.workspace || data?.data?.workspace || '').trim().toLowerCase();
            const curWs = String(workspace || '').trim().toLowerCase();
            // Fail-closed: if the event has no workspace, ignore it (prevents cross-workspace flashes).
            if (!evWs || !curWs) return;
            if (evWs !== curWs) return;
          } catch {}
          if (data.type === "message_received") {
            const msg = data.data || {};
            const userId = msg.user_id;
            const text =
              typeof msg.message === "string"
                ? msg.message
                : msg.caption || msg.type || "";
            const nowIso = new Date().toISOString();
            const msgTime = msg.timestamp || nowIso;
            setConversations((prev) => {
              const idx = prev.findIndex((c) => c.user_id === userId);
              if (idx !== -1) {
                const current = prev[idx];
                // If archived as Done, remove the tag on any new incoming message
                const oldTags = Array.isArray(current.tags) ? current.tags : [];
                const newTags = (msg.from_me ? oldTags : oldTags.filter(t => String(t || '').toLowerCase() !== 'done'));
                const updated = {
                  ...current,
                  last_message: text,
                  last_message_type: msg.type || current.last_message_type,
                  last_message_from_me: Boolean(msg.from_me),
                  last_message_status: (() => {
                    // Only consider status when the last message is from me
                    if (!msg.from_me) return current.last_message_status;
                    const rank = (s) => ({ sending: 0, sent: 1, delivered: 2, read: 3, failed: 99 }[s] ?? -1);
                    const cur = current.last_message_status;
                    const nxt = msg.status;
                    if (typeof nxt !== 'string') return cur;
                    if (!cur) return nxt;
                    return rank(nxt) >= rank(cur) ? nxt : cur;
                  })(),
                  // Always treat an incoming message as latest activity for ordering purposes
                  last_message_time: nowIso,
                  _flash_ts: (!msg.from_me ? Date.now() : (current._flash_ts || 0)),
                  unread_count:
                    activeUserRef.current?.user_id === userId
                      ? current.unread_count
                      : (current.unread_count || 0) + 1,
                  tags: newTags,
                };
                return [
                  updated,
                  ...prev.slice(0, idx),
                  ...prev.slice(idx + 1),
                ];
              }
              const newConv = {
                user_id: userId,
                name: msg.name || userId,
                last_message: text,
                last_message_type: msg.type || 'text',
                last_message_from_me: Boolean(msg.from_me),
                last_message_status: msg.from_me ? (msg.status || undefined) : undefined,
                last_message_time: nowIso,
                _flash_ts: (!msg.from_me ? Date.now() : 0),
                unread_count:
                  activeUserRef.current?.user_id === userId ? 0 : 1,
                tags: [],
              };
              return [newConv, ...prev];
            });
          }
          if (data.type === "conversation_tags_updated") {
            const d = data.data || {};
            const userId = d.user_id;
            const tags = Array.isArray(d.tags) ? d.tags : [];
            if (userId) {
              setConversations((prev) => prev.map((c) => c.user_id === userId ? { ...c, tags } : c));
              if (activeUserRef.current?.user_id === userId) {
                setActiveUser((prev) => prev ? { ...prev, tags } : prev);
              }
            }
          }
          if (data.type === "conversation_assignment_updated") {
            const d = data.data || {};
            const userId = d.user_id;
            const assignedAgent = (d.assigned_agent === null || d.assigned_agent === undefined) ? null : String(d.assigned_agent || '');
            if (userId) {
              setConversations((prev) => prev.map((c) => c.user_id === userId ? { ...c, assigned_agent: assignedAgent } : c));
              if (activeUserRef.current?.user_id === userId) {
                setActiveUser((prev) => prev ? { ...prev, assigned_agent: assignedAgent } : prev);
              }
            }
          }
        } catch (err) {
          console.error("WS message parsing failed", err);
        }
      });
    };

    connectAdmin();
    return () => {
      clearTimeout(timer);
      if (adminWsRef.current) try { adminWsRef.current.close(); } catch {}
      try { if (adminPingRef.current) clearInterval(adminPingRef.current); } catch {}
      adminPingRef.current = null;
      setAdminWsConnected(false);
    };
  }, [authReady, isLoginPath, workspace]);

  // --- Setup WebSocket for messages (with reconnection) ---
  useEffect(() => {
    let retry = 0;
    let timer = null;
    if (!activeUser?.user_id) return;
    if (wsRef.current) try { wsRef.current.close(); } catch {}

    const wsBase =
      process.env.REACT_APP_WS_URL ||
      `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/`;

    const connectUser = () => {
      const qs = new URLSearchParams();
      try {
        const t = sessionStorage.getItem('agent_access_token') || localStorage.getItem('agent_access_token');
        if (t) qs.set('token', t);
      } catch {}
      qs.set('workspace', String(workspace || 'irranova'));
      const uid = String(activeUserRef.current?.user_id || '').trim();
      if (!uid) return; // avoid connecting to /ws/?... (invalid path)
      const uidEnc = encodeURIComponent(uid);
      const ws = new WebSocket(`${wsBase}${uidEnc}?${qs.toString()}`);
      wsRef.current = ws;
      ws.addEventListener('open', () => {
        retry = 0;
        try { ws.send(JSON.stringify({ type: 'ping', ts: Date.now() })); } catch {}
      });
      ws.addEventListener('close', () => {
        // Only reconnect if we're still viewing the same conversation
        try {
          const current = String(activeUserRef.current?.user_id || '').trim();
          if (!current || current !== uid) return;
        } catch {}
        const delay = Math.min(30000, 1000 * Math.pow(2, retry++)) + Math.floor(Math.random() * 500);
        timer = setTimeout(connectUser, delay);
      });
      ws.addEventListener('error', () => {
        try { ws.close(); } catch {}
      });
      // No global conversation refetch on every WS event; admins WS updates the list
    };

    connectUser();
    return () => {
      clearTimeout(timer);
      if (wsRef.current) try { wsRef.current.close(); } catch {}
    };
  }, [activeUser?.user_id, workspace]);

  // Helper to update tags on a conversation and keep activeUser in sync
  const handleUpdateConversationTags = (userId, tags) => {
    setConversations(prev => prev.map(c => c.user_id === userId ? { ...c, tags } : c));
    if (activeUserRef.current?.user_id === userId) {
      setActiveUser(prev => prev ? { ...prev, tags } : prev);
    }
  };

  // Helper to update assignment on a conversation and keep activeUser in sync
  const handleUpdateConversationAssignee = (userId, assignedAgent) => {
    const val = (assignedAgent === null || assignedAgent === undefined || String(assignedAgent).trim() === '') ? null : String(assignedAgent);
    setConversations(prev => prev.map(c => c.user_id === userId ? { ...c, assigned_agent: val } : c));
    if (activeUserRef.current?.user_id === userId) {
      setActiveUser(prev => prev ? { ...prev, assigned_agent: val } : prev);
    }
  };

  if (isLoginPath) {
    return (
      <Suspense fallback={<div className="min-h-screen w-full flex items-center justify-center bg-gray-900 text-white">Loading…</div>}>
        <Login onSuccess={(user) => {
          try { localStorage.setItem('agent_username', user || ''); } catch {}
          window.location.replace(`/#agent=${encodeURIComponent(user || '')}`);
        }} />
      </Suspense>
    );
  }

  return (
    <AudioProvider>
    <div className="flex h-screen bg-gray-900 text-white overflow-hidden" style={{ fontSize: 'var(--app-font-size, 16px)' }}>
      {/* LEFT: Mini sidebar + Agent header + Chat list */}
      <div className="w-[30rem] min-w-[30rem] flex-shrink-0 overflow-hidden flex relative z-0 bg-gray-900">
        <MiniSidebar
          showArchive={showArchive}
          onSetShowArchive={setShowArchive}
          onToggleInternal={() => setShowInternalPanel((v) => !v)}
          onSelectInternalAgent={(username)=> { setActiveUser({ user_id: `dm:${username}`, name: `@${username}` }); setShowInternalPanel(false); }}
          onOpenSettings={() => { try { window.location.href = '/#/settings'; } catch {} }}
          currentAgent={currentAgent}
          isAdmin={isAdmin}
          workspace={workspace}
          onSwitchWorkspace={(next) => {
            try {
              const w = String(next || 'irranova').trim().toLowerCase() || 'irranova';
              try { localStorage.setItem('workspace', w); } catch {}
              // Reset view state so we don't show mixed data while switching
              setActiveUser(null);
              activeUserRef.current = null;
              setConversations([]);
              setWorkspace(w);
            } catch {}
          }}
        onStartNewChat={(digits, display) => {
          try {
            const id = String(digits);
            const name = display || id;
            setActiveUser({ user_id: id, name });
            // Ensure Inbox tab
            setShowArchive(false);
          } catch {}
        }}
        />
        <div className="flex-1 flex flex-col border-r border-gray-700 bg-gray-900 overflow-y-auto">
          <AgentHeaderBar />
          {/* InternalChannelsBar inline list removed in favor of dropdown on the sidebar icon */}
          {authReady || isLoginPath ? (
            <ChatList
              conversations={conversations}
              setActiveUser={setActiveUser}
              activeUser={activeUser}
              wsConnected={adminWsConnected}
              defaultAssignedFilter={'all'}
              showArchive={showArchive}
              currentAgent={currentAgent}
              loading={loadingConversations}
              onUpdateConversationTags={handleUpdateConversationTags}
              onUpdateConversationAssignee={handleUpdateConversationAssignee}
            onLoadMore={loadMoreConversations}
            hasMore={convHasMore}
            loadingMore={convLoadingMore}
            />
          ) : (
            <div className="p-3 text-sm text-gray-300">Checking session…</div>
          )}
        </div>
      </div>
      {/* MIDDLE: Chat window */}
      <div className="flex-1 overflow-hidden relative z-0 min-w-0">
        {/* Pass wsRef.current as prop so ChatWindow can send/receive via WebSocket */}
        {authReady || isLoginPath ? (
          <ChatWindow
            activeUser={activeUser}
            catalogProducts={catalogProducts}
            ws={wsRef.current}
            currentAgent={currentAgent}
            adminWs={adminWsRef.current}
            onUpdateConversationTags={handleUpdateConversationTags}
            onUpdateConversationAssignee={handleUpdateConversationAssignee}
            workspace={workspace}
          />
        ) : null}
        {/* Persistent audio bar above composer area */}
        <div className="absolute left-0 right-0 bottom-[88px] px-4">
          <GlobalAudioBar />
        </div>
      </div>
      {/* RIGHT: Shopify "contact info" panel, responsive (hidden on small/medium) */}
      <div className="hidden lg:block lg:w-80 lg:min-w-[18rem] lg:flex-shrink-0 border-l border-gray-700 bg-gray-900 overflow-y-auto">
        <Suspense fallback={<div className="p-3 text-sm text-gray-300">Loading Shopify panel…</div>}>
          <ShopifyIntegrationsPanel activeUser={activeUser} currentAgent={currentAgent} />
        </Suspense>
      </div>
    </div>
    </AudioProvider>
  );
}
