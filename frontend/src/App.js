// /frontend/src/App.jsx
import React, { useEffect, useState, useRef } from 'react';
import ChatList from './ChatList';
import InternalChannelsBar from './InternalChannelsBar';
import AgentHeaderBar from './AgentHeaderBar';
import ChatWindow from './ChatWindow';
import ShopifyIntegrationsPanel from './ShopifyIntegrationsPanel';
import api from './api';
import { loadConversations, saveConversations } from './chatStorage';

// Read API base from env for production/dev compatibility
// Default to relative paths if not provided
const API_BASE = process.env.REACT_APP_API_BASE || "";

export default function App() {
  const [products, setProducts] = useState([]);
  const [catalogProducts, setCatalogProducts] = useState({});
  const [conversations, setConversations] = useState([]);
  const [activeUser, setActiveUser] = useState(null);
  const [currentAgent, setCurrentAgent] = useState("");
  const [myAssignedOnly, setMyAssignedOnly] = useState(false);
  const [adminWsConnected, setAdminWsConnected] = useState(false);
  const activeUserRef = useRef(activeUser);

  // WebSocket for chat and a separate one for admin updates
  const wsRef = useRef(null);
  const adminWsRef = useRef(null);

  useEffect(() => {
    activeUserRef.current = activeUser;
  }, [activeUser]);

  // Fetch all conversations for chat list
  const fetchConversations = async () => {
    try {
      const res = await api.get(`${API_BASE}/conversations`);
      setConversations(res.data);
      saveConversations(res.data);
    } catch (err) {
      console.error('Failed to fetch conversations:', err);
      const cached = await loadConversations();
      if (cached.length > 0) {
        setConversations(cached);
      }
    }
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

  // Load conversations/products on mount
  useEffect(() => {
    loadConversations().then(cached => {
      if (cached.length > 0) {
        setConversations(cached);
      }
    });
    fetchConversations();
    fetchCatalogProducts();
    // You can remove the interval now if using WebSocket for chat!
    // const interval = setInterval(() => {
    //   fetchConversations();
    //   fetchCatalogProducts();
    // }, 5000);
    // return () => clearInterval(interval);
  }, []);

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

        if (agent) setCurrentAgent(agent);
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

  // Open a persistent WebSocket for admin notifications (with reconnection)
  useEffect(() => {
    let retry = 0;
    let timer = null;
    const wsBase =
      process.env.REACT_APP_WS_URL ||
      `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/`;

    const connectAdmin = () => {
      const ws = new WebSocket(`${wsBase}admin`);
      adminWsRef.current = ws;
      ws.addEventListener('open', () => {
        retry = 0;
        setAdminWsConnected(true);
        try { ws.send(JSON.stringify({ type: 'ping', ts: Date.now() })); } catch {}
      });
      ws.addEventListener('close', () => {
        setAdminWsConnected(false);
        const delay = Math.min(30000, 1000 * Math.pow(2, retry++)) + Math.floor(Math.random() * 500);
        timer = setTimeout(connectAdmin, delay);
      });
      ws.addEventListener('error', () => {
        setAdminWsConnected(false);
        try { ws.close(); } catch {}
      });
      ws.addEventListener('message', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.type === "message_received") {
            const msg = data.data || {};
            const userId = msg.user_id;
            const text =
              typeof msg.message === "string"
                ? msg.message
                : msg.caption || msg.type || "";
            const time = msg.timestamp || new Date().toISOString();
            setConversations((prev) => {
              const idx = prev.findIndex((c) => c.user_id === userId);
              if (idx !== -1) {
                const current = prev[idx];
                if (
                  current.last_message_time &&
                  new Date(current.last_message_time) > new Date(time)
                ) {
                  return prev;
                }
                const updated = {
                  ...current,
                  last_message: text,
                  last_message_time: time,
                  unread_count:
                    activeUserRef.current?.user_id === userId
                      ? current.unread_count
                      : (current.unread_count || 0) + 1,
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
                last_message_time: time,
                unread_count:
                  activeUserRef.current?.user_id === userId ? 0 : 1,
              };
              return [newConv, ...prev];
            });
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
      setAdminWsConnected(false);
    };
  }, []);

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
      const ws = new WebSocket(`${wsBase}${activeUserRef.current?.user_id}`);
      wsRef.current = ws;
      ws.addEventListener('open', () => {
        retry = 0;
        try { ws.send(JSON.stringify({ type: 'ping', ts: Date.now() })); } catch {}
      });
      ws.addEventListener('close', () => {
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
  }, [activeUser?.user_id]);

  return (
    <div className="flex h-screen bg-gray-900 text-white overflow-hidden">
      {/* LEFT: Agent header + Chat list */}
      <div className="w-1/3 border-r border-gray-700 overflow-hidden">
        <AgentHeaderBar
          currentAgent={currentAgent}
          onAgentChange={setCurrentAgent}
          myAssignedOnly={myAssignedOnly}
          onToggleMyAssigned={setMyAssignedOnly}
        />
        <InternalChannelsBar
          onSelectChannel={(ch)=> setActiveUser({ user_id: `team:${ch}`, name: `#${ch}` })}
          onSelectAgent={(username)=> setActiveUser({ user_id: `dm:${username}`, name: `@${username}` })}
        />
        <ChatList
          conversations={conversations}
          setActiveUser={setActiveUser}
          activeUser={activeUser}
          wsConnected={adminWsConnected}
          defaultAssignedFilter={myAssignedOnly && currentAgent ? currentAgent : 'all'}
        />
      </div>
      {/* MIDDLE: Chat window */}
      <div className="flex-1 overflow-hidden">
        {/* Pass wsRef.current as prop so ChatWindow can send/receive via WebSocket */}
        <ChatWindow
          activeUser={activeUser}
          catalogProducts={catalogProducts}
          ws={wsRef.current}
        />
      </div>
      {/* RIGHT: Shopify "contact info" panel, always visible */}
      <div className="w-96 border-l border-gray-800 bg-gray-900 overflow-y-auto">
        <ShopifyIntegrationsPanel activeUser={activeUser} />
      </div>
    </div>
  );
}
