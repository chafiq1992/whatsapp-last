import React, { useEffect, useMemo, useState } from 'react';
import api from './api';
import AnalyticsPanel from './AnalyticsPanel';

export default function AnalyticsPage() {
  const [authState, setAuthState] = useState('loading'); // loading | allowed | denied
  const [workspaces, setWorkspaces] = useState([]);
  const [workspace, setWorkspace] = useState(() => {
    try { return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova'; } catch { return 'irranova'; }
  });

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get('/auth/me');
        if (res?.data?.is_admin) setAuthState('allowed');
        else setAuthState('denied');
      } catch {
        setAuthState('denied');
      }
    })();
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await api.get('/app-config');
        const list = Array.isArray(res?.data?.workspaces) ? res.data.workspaces : [];
        const norm = list
          .map((w) => ({
            id: String(w?.id || '').trim().toLowerCase(),
            label: String(w?.label || '').trim(),
            short: String(w?.short || '').trim(),
          }))
          .filter((w) => w.id);
        if (!alive) return;
        setWorkspaces(norm);
      } catch {
        if (!alive) return;
        setWorkspaces([]);
      }
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    try { localStorage.setItem('workspace', String(workspace || '').trim().toLowerCase()); } catch {}
  }, [workspace]);

  const wsLabel = useMemo(() => {
    const w = String(workspace || '').trim().toLowerCase();
    const obj = (workspaces || []).find((x) => String(x?.id || '').trim().toLowerCase() === w) || null;
    return String(obj?.label || w || 'irranova');
  }, [workspace, workspaces]);

  return (
    <div className="h-screen w-screen bg-gray-950 text-gray-100">
      <header className="h-12 px-3 flex items-center justify-between border-b border-gray-800 bg-gray-950/70 backdrop-blur sticky top-0 z-50">
        <div className="flex items-center gap-2 min-w-0">
          <div className="text-sm font-semibold truncate">Analytics</div>
          <span className="text-xs px-2 py-0.5 rounded bg-gray-900 text-gray-200 border border-gray-800">{wsLabel}</span>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 text-sm bg-gray-900 text-gray-200 rounded border border-gray-800 hover:bg-gray-800" onClick={() => (window.location.href = '/')}>
            Inbox
          </button>
          <button className="px-3 py-1.5 text-sm bg-gray-900 text-gray-200 rounded border border-gray-800 hover:bg-gray-800" onClick={() => (window.location.href = '/#/automation-studio')}>
            Automation
          </button>
          <button className="px-3 py-1.5 text-sm bg-gray-900 text-gray-200 rounded border border-gray-800 hover:bg-gray-800" onClick={() => (window.location.href = '/#/settings')}>
            Settings
          </button>
          <select
            className="border border-gray-800 bg-gray-900 rounded px-2 py-1 text-sm"
            value={workspace}
            onChange={(e) => setWorkspace(String(e.target.value || '').trim().toLowerCase())}
            title="Workspace"
          >
            {(workspaces || []).map((w) => (
              <option key={w.id} value={w.id}>{w.label || w.id}</option>
            ))}
          </select>
        </div>
      </header>

      <div className="p-4 max-w-6xl mx-auto">
        {authState === 'loading' ? (
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4 text-sm text-gray-300">
            Loading analytics…
          </div>
        ) : authState === 'denied' ? (
          <div className="rounded-xl border border-rose-800 bg-rose-950/30 p-4 text-sm text-rose-200">
            Unauthorized. Please log in as an admin.
            <div className="mt-3">
              <button
                className="px-3 py-1.5 rounded bg-gray-900 border border-gray-800 hover:bg-gray-800"
                onClick={() => { try { window.location.href = '/login'; } catch {} }}
              >
                Go to Login
              </button>
            </div>
          </div>
        ) : (
          <AnalyticsPanel key={String(workspace || 'irranova')} />
        )}
      </div>
    </div>
  );
}


