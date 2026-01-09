import React, { useEffect, useMemo, useState } from 'react';
import api from './api';
import AnalyticsPanel from './AnalyticsPanel';

export default function AnalyticsPage() {
  const [allowed, setAllowed] = useState(false);
  const [workspaces, setWorkspaces] = useState([]);
  const [workspace, setWorkspace] = useState(() => {
    try { return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova'; } catch { return 'irranova'; }
  });

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get('/auth/me');
        if (res?.data?.is_admin) setAllowed(true);
        else window.location.replace('/');
      } catch {
        window.location.replace('/login');
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

  if (!allowed) return null;

  return (
    <div className="h-screen w-screen bg-white">
      <header className="h-12 px-3 flex items-center justify-between border-b bg-white/70 backdrop-blur sticky top-0 z-50">
        <div className="flex items-center gap-2 min-w-0">
          <div className="text-sm font-semibold text-gray-800 truncate">Analytics</div>
          <span className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 border">{wsLabel}</span>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 text-sm bg-gray-200 text-gray-900 rounded border border-gray-300" onClick={() => (window.location.href = '/')}>
            Inbox
          </button>
          <button className="px-3 py-1.5 text-sm bg-gray-800 text-white rounded" onClick={() => (window.location.href = '/#/automation-studio')}>
            Automation
          </button>
          <button className="px-3 py-1.5 text-sm bg-gray-200 text-gray-900 rounded border border-gray-300" onClick={() => (window.location.href = '/#/settings')}>
            Settings
          </button>
          <select
            className="border rounded px-2 py-1 text-sm"
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

      {/* AnalyticsPanel currently uses a dark card theme; wrap it for readability */}
      <div className="p-4 max-w-6xl mx-auto">
        <div className="rounded-xl border bg-gray-900 text-gray-100 p-4">
          <AnalyticsPanel key={String(workspace || 'irranova')} />
        </div>
      </div>
    </div>
  );
}


