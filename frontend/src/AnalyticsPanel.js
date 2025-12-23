import React, { useEffect, useMemo, useState } from 'react';
import api from './api';

function toIsoStart(date) {
  try {
    const d = new Date(date);
    if (Number.isNaN(d.getTime())) return null;
    return new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0)).toISOString();
  } catch { return null; }
}

function toIsoEnd(date) {
  try {
    const d = new Date(date);
    if (Number.isNaN(d.getTime())) return null;
    return new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59)).toISOString();
  } catch { return null; }
}

function formatDuration(seconds) {
  if (seconds == null || Number.isNaN(seconds)) return '—';
  const s = Math.max(0, Math.round(seconds));
  const m = Math.floor(s / 60);
  const ss = s % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const mm = m % 60;
    return `${h}h ${mm}m`;
  }
  return `${m}m ${ss}s`;
}

export default function AnalyticsPanel() {
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState([]);
  const [shopify, setShopify] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [shopifyError, setShopifyError] = useState('');
  const [period, setPeriod] = useState('30d'); // today | 7d | 30d | 90d | custom
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  const [shopifyMetric, setShopifyMetric] = useState('initiated'); // initiated | inbound_messages | clicks | orders_created

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get('/admin/agents');
        setAgents(Array.isArray(res.data) ? res.data : []);
      } catch {}
    })();
  }, []);

  const computeRange = () => {
    const now = new Date();
    const end = now.toISOString();
    if (period === 'today') {
      const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0)).toISOString();
      return { start, end };
    }
    if (period === '7d' || period === '30d' || period === '90d') {
      const days = period === '7d' ? 7 : (period === '30d' ? 30 : 90);
      const start = new Date(now.getTime() - days * 864e5).toISOString();
      return { start, end };
    }
    if (period === 'custom' && customStart && customEnd) {
      const s = toIsoStart(customStart);
      const e = toIsoEnd(customEnd);
      if (s && e) return { start: s, end: e };
    }
    // default 30d
    return { start: new Date(now.getTime() - 30 * 864e5).toISOString(), end };
  };

  const fetchStats = async () => {
    setLoading(true);
    setError('');
    setShopifyError('');
    try {
      const { start, end } = computeRange();
      const qs = new URLSearchParams({ start, end }).toString();
      const res = await api.get(`/analytics/agents?${qs}`);
      setStats(Array.isArray(res.data) ? res.data : []);

      // Shopify / website WhatsApp analytics (admin-only endpoint, same permissions as /analytics/agents)
      try {
        const spanMs = Math.abs(new Date(end).getTime() - new Date(start).getTime());
        const bucket = spanMs <= (3 * 24 * 60 * 60 * 1000) ? 'hour' : 'day';
        const qs2 = new URLSearchParams({ start, end, bucket }).toString();
        const r2 = await api.get(`/analytics/inbox/shopify?${qs2}`);
        setShopify(r2?.data || null);
      } catch (e) {
        setShopify(null);
        setShopifyError('Failed to load website WhatsApp analytics');
      }
    } catch (e) {
      setError('Failed to load analytics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [period]);

  const totals = useMemo(() => {
    const totalReceived = stats.reduce((s, x) => s + (Number(x.messages_received || 0) || 0), 0);
    const totalRepliedTo = stats.reduce((s, x) => s + (Number(x.messages_replied_to || 0) || 0), 0);
    const totalSent = stats.reduce((s, x) => s + (Number(x.messages_sent || 0) || 0), 0);
    const totalOrders = stats.reduce((s, x) => s + (Number(x.orders_created || 0) || 0), 0);
    const totalAgents = agents.length;
    return { totalReceived, totalRepliedTo, totalSent, totalOrders, totalAgents };
  }, [stats, agents]);

  const nameOf = (username) => {
    const a = agents.find((x) => x.username === username);
    return a?.name || username;
  };

  const maxReplied = Math.max(1, ...stats.map((x) => Number(x.messages_replied_to || 0)));
  const maxOrders = Math.max(1, ...stats.map((x) => Number(x.orders_created || 0)));

  const shopSeries = Array.isArray(shopify?.series) ? shopify.series : [];
  const shopTotals = shopify?.totals || {};
  const metricKey = shopifyMetric;
  const maxShop = Math.max(1, ...shopSeries.map((x) => Number(x?.[metricKey] || 0)));

  const formatBucketLabel = (b) => {
    try {
      // b comes as "YYYY-MM-DDTHH:00:00" or "YYYY-MM-DDT00:00:00"
      const d = new Date(b);
      if (Number.isNaN(d.getTime())) return String(b || '');
      if ((shopify?.bucket || '') === 'hour') {
        return d.toISOString().slice(11, 16); // HH:MM
      }
      return d.toISOString().slice(0, 10); // YYYY-MM-DD
    } catch {
      return String(b || '');
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-lg font-semibold">Analytics</div>
        <div className="flex items-center gap-2">
          {['today','7d','30d','90d','custom'].map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1 rounded ${period===p ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300'}`}
            >{p.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {period === 'custom' && (
        <div className="flex items-end gap-2">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Start date</label>
            <input type="date" value={customStart} onChange={(e)=>setCustomStart(e.target.value)} className="p-2 bg-gray-800 rounded" />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">End date</label>
            <input type="date" value={customEnd} onChange={(e)=>setCustomEnd(e.target.value)} className="p-2 bg-gray-800 rounded" />
          </div>
          <button className="px-3 py-2 bg-blue-600 rounded" onClick={fetchStats}>Apply</button>
        </div>
      )}

      {error && <div className="text-red-400 text-sm">{error}</div>}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="bg-gray-800 rounded p-4 border border-gray-700">
          <div className="text-sm text-gray-400">Total received</div>
          <div className="text-2xl font-bold">{totals.totalReceived}</div>
        </div>
        <div className="bg-gray-800 rounded p-4 border border-gray-700">
          <div className="text-sm text-gray-400">Total replied-to</div>
          <div className="text-2xl font-bold">{totals.totalRepliedTo}</div>
        </div>
        <div className="bg-gray-800 rounded p-4 border border-gray-700">
          <div className="text-sm text-gray-400">Total sent</div>
          <div className="text-2xl font-bold">{totals.totalSent}</div>
        </div>
        <div className="bg-gray-800 rounded p-4 border border-gray-700">
          <div className="text-sm text-gray-400">Total orders</div>
          <div className="text-2xl font-bold">{totals.totalOrders}</div>
        </div>
      </div>

      <div className="bg-gray-800 rounded p-4 border border-gray-700">
        <div className="flex items-center justify-between gap-3 mb-2">
          <div className="font-medium">Website WhatsApp icon (Shopify) analytics</div>
          <div className="flex items-center gap-2">
            {['initiated','inbound_messages','clicks','orders_created'].map((k) => (
              <button
                key={k}
                onClick={() => setShopifyMetric(k)}
                className={`px-2 py-1 rounded text-xs ${shopifyMetric===k ? 'bg-blue-600 text-white' : 'bg-gray-900 text-gray-300'}`}
                title={k}
              >
                {k.replaceAll('_',' ').toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {shopifyError && <div className="text-red-400 text-sm mb-2">{shopifyError}</div>}

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mb-4">
          <div className="bg-gray-900 rounded p-3 border border-gray-700">
            <div className="text-xs text-gray-400">Clicks</div>
            <div className="text-xl font-bold">{Number(shopTotals.clicks || 0)}</div>
          </div>
          <div className="bg-gray-900 rounded p-3 border border-gray-700">
            <div className="text-xs text-gray-400">Initiated chats</div>
            <div className="text-xl font-bold">{Number(shopTotals.initiated_conversations || 0)}</div>
          </div>
          <div className="bg-gray-900 rounded p-3 border border-gray-700">
            <div className="text-xs text-gray-400">Inbound msgs</div>
            <div className="text-xl font-bold">{Number(shopTotals.inbound_messages || 0)}</div>
          </div>
          <div className="bg-gray-900 rounded p-3 border border-gray-700">
            <div className="text-xs text-gray-400">Orders created</div>
            <div className="text-xl font-bold">{Number(shopTotals.orders_created || 0)}</div>
          </div>
          <div className="bg-gray-900 rounded p-3 border border-gray-700">
            <div className="text-xs text-gray-400">Orders / initiated</div>
            <div className="text-xl font-bold">{((Number(shopTotals.orders_per_initiated || 0)) * 100).toFixed(1)}%</div>
          </div>
        </div>

        <div className="overflow-auto">
          <div className="flex items-end gap-1 h-32 min-w-[520px]">
            {shopSeries.map((x) => {
              const v = Number(x?.[metricKey] || 0);
              const h = Math.round((v / maxShop) * 100);
              return (
                <div key={x.bucket} className="flex flex-col items-center gap-1">
                  <div
                    className="w-3 bg-blue-600 rounded-t"
                    style={{ height: `${Math.max(1, h)}%` }}
                    title={`${formatBucketLabel(x.bucket)} • ${metricKey}: ${v}`}
                  />
                  <div className="text-[10px] text-gray-500 rotate-[-45deg] origin-top-left whitespace-nowrap">
                    {formatBucketLabel(x.bucket)}
                  </div>
                </div>
              );
            })}
            {shopSeries.length === 0 && <div className="text-sm text-gray-400">No data</div>}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 rounded p-4 border border-gray-700">
          <div className="font-medium mb-2">Inbound messages replied-to (by agent)</div>
          <div className="space-y-2">
            {stats.map((s) => (
              <div key={s.agent} className="flex items-center gap-2">
                <div className="w-32 text-sm text-gray-300 truncate" title={nameOf(s.agent)}>{nameOf(s.agent)}</div>
                <div className="flex-1 h-4 bg-gray-900 rounded overflow-hidden">
                  <div className="h-4 bg-blue-600" style={{ width: `${Math.round((Number(s.messages_replied_to||0)/maxReplied)*100)}%` }}></div>
                </div>
                <div className="w-12 text-right text-sm">{s.messages_replied_to || 0}</div>
              </div>
            ))}
            {stats.length === 0 && <div className="text-sm text-gray-400">No data</div>}
          </div>
        </div>
        <div className="bg-gray-800 rounded p-4 border border-gray-700">
          <div className="font-medium mb-2">Orders by agent</div>
          <div className="space-y-2">
            {stats.map((s) => (
              <div key={s.agent} className="flex items-center gap-2">
                <div className="w-32 text-sm text-gray-300 truncate" title={nameOf(s.agent)}>{nameOf(s.agent)}</div>
                <div className="flex-1 h-4 bg-gray-900 rounded overflow-hidden">
                  <div className="h-4 bg-emerald-600" style={{ width: `${Math.round((Number(s.orders_created||0)/maxOrders)*100)}%` }}></div>
                </div>
                <div className="w-12 text-right text-sm">{s.orders_created || 0}</div>
              </div>
            ))}
            {stats.length === 0 && <div className="text-sm text-gray-400">No data</div>}
          </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded p-4 border border-gray-700">
        <div className="font-medium mb-2">Per-agent details</div>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-left">
                <th className="py-1 pr-2">Agent</th>
                <th className="py-1 pr-2">Received</th>
                <th className="py-1 pr-2">Replied-to</th>
                <th className="py-1 pr-2">Sent</th>
                <th className="py-1 pr-2">Orders</th>
                <th className="py-1 pr-2">Avg reply time</th>
              </tr>
            </thead>
            <tbody>
              {stats.map((s) => (
                <tr key={s.agent} className="border-t border-gray-700">
                  <td className="py-1 pr-2">{nameOf(s.agent)}</td>
                  <td className="py-1 pr-2">{s.messages_received || 0}</td>
                  <td className="py-1 pr-2">{s.messages_replied_to || 0}</td>
                  <td className="py-1 pr-2">{s.messages_sent || 0}</td>
                  <td className="py-1 pr-2">{s.orders_created || 0}</td>
                  <td className="py-1 pr-2">{formatDuration(s.avg_response_seconds)}</td>
                </tr>
              ))}
              {stats.length === 0 && (
                <tr><td colSpan={6} className="py-2 text-gray-400">No data</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


