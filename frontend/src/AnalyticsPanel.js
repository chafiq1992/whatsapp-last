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
        const status = e?.response?.status;
        const payload = e?.response?.data;
        if (status === 401) setShopifyError('Website WhatsApp analytics: Unauthorized (please login again)');
        else if (status === 403) setShopifyError('Website WhatsApp analytics: Admin required');
        else if (status === 500) {
          // Backend returns a structured payload with more detail.
          const detail = (payload && (payload.detail || payload.error)) ? String(payload.detail || payload.error) : '';
          const hint = (payload && payload.hint) ? String(payload.hint) : '';
          const ws = (payload && payload.workspace) ? String(payload.workspace) : '';
          const extra = [detail, ws ? `workspace=${ws}` : '', hint].filter(Boolean).join(' • ');
          setShopifyError(extra ? `Failed to load website WhatsApp analytics • ${extra}` : 'Failed to load website WhatsApp analytics');
        } else setShopifyError('Failed to load website WhatsApp analytics');
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
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xl font-semibold tracking-tight text-slate-900">Analytics</div>
          <div className="text-sm text-slate-500">Agent performance and website WhatsApp funnel</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {['today','7d','30d','90d','custom'].map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1.5 rounded-full text-sm border transition ${
                period===p
                  ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm'
                  : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
              }`}
            >{p.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {period === 'custom' && (
        <div className="flex flex-col sm:flex-row sm:items-end gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Start date</label>
            <input type="date" value={customStart} onChange={(e)=>setCustomStart(e.target.value)} className="p-2 bg-white rounded-xl border border-slate-200 text-slate-900" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">End date</label>
            <input type="date" value={customEnd} onChange={(e)=>setCustomEnd(e.target.value)} className="p-2 bg-white rounded-xl border border-slate-200 text-slate-900" />
          </div>
          <button className="px-4 py-2 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 shadow-sm" onClick={fetchStats}>Apply</button>
        </div>
      )}

      {error && (
        <div className="rounded-2xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
          <div className="text-sm text-slate-500">Total received</div>
          <div className="text-2xl font-semibold text-slate-900">{totals.totalReceived}</div>
        </div>
        <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
          <div className="text-sm text-slate-500">Total replied-to</div>
          <div className="text-2xl font-semibold text-slate-900">{totals.totalRepliedTo}</div>
        </div>
        <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
          <div className="text-sm text-slate-500">Total sent</div>
          <div className="text-2xl font-semibold text-slate-900">{totals.totalSent}</div>
        </div>
        <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
          <div className="text-sm text-slate-500">Total orders</div>
          <div className="text-2xl font-semibold text-slate-900">{totals.totalOrders}</div>
        </div>
      </div>

      <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 mb-2">
          <div className="font-medium text-slate-900">Website WhatsApp icon (Shopify) analytics</div>
          <div className="flex flex-wrap items-center gap-2">
            {['initiated','inbound_messages','clicks','orders_created'].map((k) => (
              <button
                key={k}
                onClick={() => setShopifyMetric(k)}
                className={`px-2.5 py-1.5 rounded-full text-xs border transition ${
                  shopifyMetric===k
                    ? 'bg-indigo-600 text-white border-indigo-600'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                }`}
                title={k}
              >
                {k.replaceAll('_',' ').toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {shopifyError && (
          <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800 mb-3">
            {shopifyError}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3 mb-4">
          <div className="bg-slate-50 rounded-2xl p-3 border border-slate-200">
            <div className="text-xs text-slate-500">Clicks</div>
            <div className="text-xl font-semibold text-slate-900">{Number(shopTotals.clicks || 0)}</div>
          </div>
          <div className="bg-slate-50 rounded-2xl p-3 border border-slate-200">
            <div className="text-xs text-slate-500">Initiated chats</div>
            <div className="text-xl font-semibold text-slate-900">{Number(shopTotals.initiated_conversations || 0)}</div>
          </div>
          <div className="bg-slate-50 rounded-2xl p-3 border border-slate-200">
            <div className="text-xs text-slate-500">Inbound msgs</div>
            <div className="text-xl font-semibold text-slate-900">{Number(shopTotals.inbound_messages || 0)}</div>
          </div>
          <div className="bg-slate-50 rounded-2xl p-3 border border-slate-200">
            <div className="text-xs text-slate-500">Orders created</div>
            <div className="text-xl font-semibold text-slate-900">{Number(shopTotals.orders_created || 0)}</div>
          </div>
          <div className="bg-slate-50 rounded-2xl p-3 border border-slate-200">
            <div className="text-xs text-slate-500">Orders / initiated</div>
            <div className="text-xl font-semibold text-slate-900">{((Number(shopTotals.orders_per_initiated || 0)) * 100).toFixed(1)}%</div>
          </div>
        </div>

        <div className="overflow-auto">
          <div className="flex items-end gap-1 h-36 min-w-[520px]">
            {shopSeries.map((x) => {
              const v = Number(x?.[metricKey] || 0);
              const h = Math.round((v / maxShop) * 100);
              return (
                <div key={x.bucket} className="flex flex-col items-center gap-1">
                  <div
                    className="w-3 rounded-t bg-gradient-to-t from-indigo-500 to-sky-400"
                    style={{ height: `${Math.max(1, h)}%` }}
                    title={`${formatBucketLabel(x.bucket)} • ${metricKey}: ${v}`}
                  />
                  <div className="text-[10px] text-slate-500 rotate-[-45deg] origin-top-left whitespace-nowrap">
                    {formatBucketLabel(x.bucket)}
                  </div>
                </div>
              );
            })}
            {shopSeries.length === 0 && <div className="text-sm text-slate-500">No data</div>}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
          <div className="font-medium text-slate-900 mb-2">Inbound messages replied-to (by agent)</div>
          <div className="space-y-2">
            {stats.map((s) => (
              <div key={s.agent} className="flex items-center gap-2">
                <div className="w-32 text-sm text-slate-700 truncate" title={nameOf(s.agent)}>{nameOf(s.agent)}</div>
                <div className="flex-1 h-3.5 bg-slate-100 rounded-full overflow-hidden">
                  <div className="h-3.5 bg-indigo-600" style={{ width: `${Math.round((Number(s.messages_replied_to||0)/maxReplied)*100)}%` }}></div>
                </div>
                <div className="w-12 text-right text-sm text-slate-700">{s.messages_replied_to || 0}</div>
              </div>
            ))}
            {stats.length === 0 && <div className="text-sm text-slate-500">No data</div>}
          </div>
        </div>
        <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
          <div className="font-medium text-slate-900 mb-2">Orders by agent</div>
          <div className="space-y-2">
            {stats.map((s) => (
              <div key={s.agent} className="flex items-center gap-2">
                <div className="w-32 text-sm text-slate-700 truncate" title={nameOf(s.agent)}>{nameOf(s.agent)}</div>
                <div className="flex-1 h-3.5 bg-slate-100 rounded-full overflow-hidden">
                  <div className="h-3.5 bg-emerald-600" style={{ width: `${Math.round((Number(s.orders_created||0)/maxOrders)*100)}%` }}></div>
                </div>
                <div className="w-12 text-right text-sm text-slate-700">{s.orders_created || 0}</div>
              </div>
            ))}
            {stats.length === 0 && <div className="text-sm text-slate-500">No data</div>}
          </div>
        </div>
      </div>

      <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm">
        <div className="font-medium text-slate-900 mb-2">Per-agent details</div>
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-500 text-left">
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
                <tr key={s.agent} className="border-t border-slate-200 text-slate-800">
                  <td className="py-1 pr-2">{nameOf(s.agent)}</td>
                  <td className="py-1 pr-2">{s.messages_received || 0}</td>
                  <td className="py-1 pr-2">{s.messages_replied_to || 0}</td>
                  <td className="py-1 pr-2">{s.messages_sent || 0}</td>
                  <td className="py-1 pr-2">{s.orders_created || 0}</td>
                  <td className="py-1 pr-2">{formatDuration(s.avg_response_seconds)}</td>
                </tr>
              ))}
              {stats.length === 0 && (
                <tr><td colSpan={6} className="py-2 text-slate-500">No data</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


