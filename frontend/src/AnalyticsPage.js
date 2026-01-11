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
    <div className="min-h-screen w-full bg-slate-50 text-slate-900">
      <header className="h-14 px-4 flex items-center justify-between border-b border-slate-200 bg-white/80 backdrop-blur sticky top-0 z-50">
        <div className="flex items-center gap-2 min-w-0">
          <div className="text-sm font-semibold truncate">Analytics</div>
          <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-800 border border-indigo-100">
            {wsLabel}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 text-sm bg-white text-slate-800 rounded-lg border border-slate-200 hover:bg-slate-50" onClick={() => (window.location.href = '/')}>
            Inbox
          </button>
          <button className="px-3 py-1.5 text-sm bg-white text-slate-800 rounded-lg border border-slate-200 hover:bg-slate-50" onClick={() => (window.location.href = '/#/automation-studio')}>
            Automation
          </button>
          <button className="px-3 py-1.5 text-sm bg-white text-slate-800 rounded-lg border border-slate-200 hover:bg-slate-50" onClick={() => (window.location.href = '/#/settings')}>
            Settings
          </button>
          <select
            className="border border-slate-200 bg-white rounded-lg px-2 py-1.5 text-sm text-slate-800"
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

      <div className="w-full px-4 sm:px-6 lg:px-8 py-6">
        {authState === 'loading' ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm">
            Loading analytics…
          </div>
        ) : authState === 'denied' ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800 shadow-sm">
            Unauthorized. Please log in as an admin.
            <div className="mt-3">
              <button
                className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50"
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


