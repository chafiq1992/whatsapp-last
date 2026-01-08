import React, { useEffect, useState } from 'react';
import api from './api';
import AutomationStudio from './AutomationStudio';

export default function StudioPage() {
  const [allowed, setAllowed] = useState(false);
  const [workspaces, setWorkspaces] = useState([]);
  const [workspace, setWorkspace] = useState(() => {
    try { return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova'; } catch { return 'irranova'; }
  });
  useEffect(() => {
    (async () => {
      try {
        const res = await api.get('/auth/me');
        if (res?.data?.is_admin) {
          setAllowed(true);
        } else {
          window.location.replace('/');
        }
      } catch (e) {
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

  const nextWorkspaceId = (() => {
    try {
      const wsList = workspaces.length ? workspaces : [{ id: 'irranova' }, { id: 'irrakids' }];
      const idx = wsList.findIndex((w) => w.id === workspace);
      const next = wsList[(idx >= 0 ? (idx + 1) : 0) % Math.max(1, wsList.length)];
      return String(next?.id || '').trim().toLowerCase();
    } catch {
      return '';
    }
  })();

  if (!allowed) return null;

  return (
    <div className="h-screen w-screen bg-white">
      <div className="absolute top-2 left-2 z-50">
        <div className="flex items-center gap-2">
          <button
            className="px-3 py-1.5 text-sm bg-gray-800 text-white rounded"
            onClick={() => (window.location.href = '/')}
          >
            ← Back to Inbox
          </button>
          <button
            className="px-3 py-1.5 text-sm bg-gray-200 text-gray-900 rounded border border-gray-300"
            title="Switch workspace"
            onClick={() => {
              try {
                const next = nextWorkspaceId;
                if (!next) return;
                try { localStorage.setItem('workspace', next); } catch {}
                setWorkspace(next);
              } catch {}
            }}
          >
            Workspace: {String(workspace || '').toUpperCase()}
          </button>
        </div>
      </div>
      <AutomationStudio />
    </div>
  );
}


