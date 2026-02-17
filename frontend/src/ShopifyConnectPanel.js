import React, { useEffect, useMemo, useState } from 'react';
import api from './api';

function normalizeWorkspaceId(v) {
  try {
    return String(v || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '');
  } catch {
    return '';
  }
}

function getQueryParamFromHash(name) {
  try {
    // hash looks like "#/settings/stores?connected=1&workspace=irranova"
    const h = String(window.location.hash || '');
    const q = h.includes('?') ? h.split('?', 2)[1] : '';
    const params = new URLSearchParams(q);
    return params.get(name);
  } catch {
    return null;
  }
}

export default function ShopifyConnectPanel({ workspace, setWorkspace, workspaces = [] }) {
  const [shop, setShop] = useState('');
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const connectedFlag = useMemo(() => getQueryParamFromHash('connected'), []);

  const wsNorm = useMemo(() => normalizeWorkspaceId(workspace) || 'irranova', [workspace]);

  // If callback redirected with workspace=..., switch UI workspace to match
  useEffect(() => {
    const wsFromUrl = normalizeWorkspaceId(getQueryParamFromHash('workspace') || '');
    if (wsFromUrl && wsFromUrl !== wsNorm) {
      try { localStorage.setItem('workspace', wsFromUrl); } catch {}
      if (typeof setWorkspace === 'function') setWorkspace(wsFromUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    try {
      const key = `shopifyConnectShop:${wsNorm}`;
      const prev = (localStorage.getItem(key) || '').trim();
      if (prev) setShop(prev);
    } catch {}
  }, [wsNorm]);

  useEffect(() => {
    try {
      const key = `shopifyConnectShop:${wsNorm}`;
      localStorage.setItem(key, String(shop || ''));
    } catch {}
  }, [wsNorm, shop]);

  const refreshStatus = async () => {
    setBusy(true);
    setErr('');
    try {
      const res = await api.get(`/admin/shopify/oauth/status?workspace=${encodeURIComponent(wsNorm)}`, {
        headers: { 'X-Workspace': wsNorm },
      });
      setStatus(res?.data || null);
    } catch (e) {
      const d = e?.response?.data;
      setStatus(d || null);
      setErr(String(d?.detail || e?.message || 'Failed to fetch status'));
    } finally {
      setBusy(false);
    }
  };

  const oauthEnabled = !!status?.oauth_enabled;

  const startOAuth = () => {
    setErr('');
    if (!oauthEnabled) {
      setErr('OAuth is disabled for this store. Use env token config for irrakids.');
      return;
    }
    if (!String(shop || '').trim()) {
      setErr('Enter a shop domain like irranova.myshopify.com');
      return;
    }
    const url = `/admin/shopify/oauth/start?workspace=${encodeURIComponent(wsNorm)}&shop=${encodeURIComponent(shop)}`;
    window.location.href = url;
  };

  const clearOAuth = async () => {
    setBusy(true);
    setErr('');
    try {
      await api.post(`/admin/shopify/oauth/clear?workspace=${encodeURIComponent(wsNorm)}`, null, {
        headers: { 'X-Workspace': wsNorm },
      });
      await refreshStatus();
    } catch (e) {
      const d = e?.response?.data;
      setErr(String(d?.detail || e?.message || 'Failed to disconnect'));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    refreshStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsNorm]);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white/70 backdrop-blur shadow-sm">
      <div className="px-4 py-3 border-b">
        <div className="text-lg font-semibold">Shopify Connect</div>
        <div className="text-sm text-slate-600 mt-1">
          Connect the public app (OAuth) for <span className="font-semibold">irranova</span>. Irrakids stays on the old env token method.
        </div>
      </div>

      <div className="p-4 space-y-4">
        {connectedFlag === '1' && (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 text-emerald-900 px-4 py-3 text-sm">
            Install completed. Click <span className="font-semibold">Refresh status</span> to confirm.
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="block">
            <div className="text-xs font-semibold text-slate-600">Store</div>
            <select
              value={wsNorm}
              onChange={(e) => {
                const next = normalizeWorkspaceId(e.target.value);
                try { localStorage.setItem('workspace', next); } catch {}
                if (typeof setWorkspace === 'function') setWorkspace(next);
              }}
              className="mt-1 w-full text-sm border border-slate-300 rounded-xl px-3 py-2 bg-white"
            >
              {(workspaces || []).map((w) => (
                <option key={w.id} value={w.id}>{w.label || w.id}</option>
              ))}
            </select>
          </label>

          <label className="block">
            <div className="text-xs font-semibold text-slate-600">Shop domain</div>
            <input
              value={shop}
              onChange={(e) => setShop(e.target.value)}
              placeholder="irranova.myshopify.com"
              className="mt-1 w-full text-sm border border-slate-300 rounded-xl px-3 py-2"
            />
            {!oauthEnabled && (
              <div className="mt-1 text-[11px] text-slate-500">
                OAuth is disabled for this store. Use env token config for irrakids.
              </div>
            )}
          </label>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={startOAuth}
            className={`px-4 py-2 rounded-xl text-sm font-semibold text-white ${oauthEnabled ? 'bg-blue-600 hover:bg-blue-700' : 'bg-slate-400'}`}
            type="button"
          >
            Connect (OAuth install)
          </button>
          <button
            onClick={refreshStatus}
            disabled={busy}
            className="px-4 py-2 rounded-xl text-sm font-semibold border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-60"
            type="button"
          >
            {busy ? 'Refreshing…' : 'Refresh status'}
          </button>
          <button
            onClick={clearOAuth}
            disabled={busy}
            className="px-4 py-2 rounded-xl text-sm font-semibold border border-rose-300 bg-rose-50 text-rose-800 hover:bg-rose-100 disabled:opacity-60"
            type="button"
            title="Disconnect OAuth (clears DB token for this workspace)"
          >
            Disconnect
          </button>
        </div>

        {err && (
          <div className="rounded-xl border border-amber-200 bg-amber-50 text-amber-900 px-4 py-3 text-sm">
            {err}
          </div>
        )}

        <div>
          <div className="text-xs font-semibold text-slate-600">Status</div>
          <pre className="mt-2 text-[12px] bg-slate-950 text-slate-100 rounded-xl p-3 overflow-x-auto">
            {JSON.stringify(status || { connected: false, shop: null, scopes: null, oauth_enabled: false }, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

