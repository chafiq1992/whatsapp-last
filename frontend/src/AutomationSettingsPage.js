import React, { useEffect, useMemo, useState } from 'react';
import api from './api';

function normalizeWorkspaceId(v) {
  try {
    return String(v || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '');
  } catch {
    return '';
  }
}

export default function AutomationSettingsPage() {
  const [allowed, setAllowed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [workspaces, setWorkspaces] = useState([]);
  const [workspace, setWorkspace] = useState(() => {
    try { return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova'; } catch { return 'irranova'; }
  });

  const [wsLabelDraft, setWsLabelDraft] = useState('');
  const [wsShortDraft, setWsShortDraft] = useState('');

  const [addDraft, setAddDraft] = useState({ id: '', label: '', short: '', copy_from: '' });
  const [savingWorkspace, setSavingWorkspace] = useState(false);

  const [catalogFilters, setCatalogFilters] = useState([
    { label: 'Girls', query: 'girls', match: 'includes' },
    { label: 'Boys', query: 'boys', match: 'includes' },
    { label: 'All', type: 'all' },
  ]);
  const [savingCatalog, setSavingCatalog] = useState(false);

  const [envDraft, setEnvDraft] = useState({
    allowed_phone_number_ids: '',
    survey_test_numbers: '',
    auto_reply_test_numbers: '',
    waba_id: '',
    catalog_id: '',
    phone_number_id: '',
  });
  const [savingEnv, setSavingEnv] = useState(false);

  const selectedWsObj = useMemo(() => {
    const ws = normalizeWorkspaceId(workspace);
    return (workspaces || []).find((w) => normalizeWorkspaceId(w.id) === ws) || null;
  }, [workspaces, workspace]);

  const loadWorkspaces = async () => {
    const res = await api.get('/admin/workspaces');
    const list = Array.isArray(res?.data?.workspaces) ? res.data.workspaces : [];
    const norm = list
      .map((w) => ({
        id: normalizeWorkspaceId(w?.id),
        label: String(w?.label || '').trim(),
        short: String(w?.short || '').trim(),
        source: String(w?.source || '').trim(),
      }))
      .filter((w) => w.id);
    setWorkspaces(norm);
    return norm;
  };

  const loadCatalogFilters = async (ws) => {
    const res = await api.get('/admin/catalog-filters', { headers: { 'X-Workspace': normalizeWorkspaceId(ws) } });
    const arr = Array.isArray(res?.data?.catalogFilters) ? res.data.catalogFilters : null;
    if (arr && arr.length >= 2) setCatalogFilters(arr);
  };

  const loadInboxEnv = async (ws) => {
    const res = await api.get('/admin/inbox-env', { headers: { 'X-Workspace': normalizeWorkspaceId(ws) } });
    const d = res?.data || {};
    const join = (arr) => (Array.isArray(arr) ? arr.filter(Boolean).join('\n') : '');
    setEnvDraft({
      allowed_phone_number_ids: join(d.allowed_phone_number_ids),
      survey_test_numbers: join(d.survey_test_numbers),
      auto_reply_test_numbers: join(d.auto_reply_test_numbers),
      waba_id: String(d.waba_id || ''),
      catalog_id: String(d.catalog_id || ''),
      phone_number_id: String(d.phone_number_id || ''),
    });
  };

  const refreshAllForWorkspace = async (ws) => {
    await Promise.allSettled([loadCatalogFilters(ws), loadInboxEnv(ws)]);
  };

  useEffect(() => {
    (async () => {
      setError('');
      setLoading(true);
      try {
        const res = await api.get('/auth/me');
        if (!res?.data?.is_admin) {
          window.location.replace('/');
          return;
        }
        setAllowed(true);
        const list = await loadWorkspaces();
        const ws = normalizeWorkspaceId(workspace) || normalizeWorkspaceId(list?.[0]?.id) || 'irranova';
        try { localStorage.setItem('workspace', ws); } catch {}
        setWorkspace(ws);
        const obj = (list || []).find((x) => x.id === ws) || null;
        setWsLabelDraft(String(obj?.label || ''));
        setWsShortDraft(String(obj?.short || ''));
        await refreshAllForWorkspace(ws);
      } catch (e) {
        window.location.replace('/login');
        return;
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!allowed) return;
    const ws = normalizeWorkspaceId(workspace);
    if (!ws) return;
    try { localStorage.setItem('workspace', ws); } catch {}
    const obj = (workspaces || []).find((x) => x.id === ws) || null;
    setWsLabelDraft(String(obj?.label || ''));
    setWsShortDraft(String(obj?.short || ''));
    refreshAllForWorkspace(ws);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace]);

  const saveWorkspaceMeta = async () => {
    const ws = normalizeWorkspaceId(workspace);
    if (!ws) return;
    setSavingWorkspace(true);
    setError('');
    try {
      await api.post('/admin/workspaces', { id: ws, label: wsLabelDraft, short: wsShortDraft });
      await loadWorkspaces();
    } catch (e) {
      setError('Failed to save workspace metadata.');
    } finally {
      setSavingWorkspace(false);
    }
  };

  const saveCatalog = async () => {
    const ws = normalizeWorkspaceId(workspace);
    if (!ws) return;
    setSavingCatalog(true);
    setError('');
    try {
      await api.post('/admin/catalog-filters', { catalogFilters }, { headers: { 'X-Workspace': ws } });
    } catch (e) {
      setError('Failed to save catalog filters.');
    } finally {
      setSavingCatalog(false);
    }
  };

  const saveEnv = async () => {
    const ws = normalizeWorkspaceId(workspace);
    if (!ws) return;
    setSavingEnv(true);
    setError('');
    try {
      await api.post('/admin/inbox-env', {
        allowed_phone_number_ids: envDraft.allowed_phone_number_ids,
        survey_test_numbers: envDraft.survey_test_numbers,
        auto_reply_test_numbers: envDraft.auto_reply_test_numbers,
        waba_id: envDraft.waba_id,
        catalog_id: envDraft.catalog_id,
        phone_number_id: envDraft.phone_number_id,
      }, { headers: { 'X-Workspace': ws } });
      await loadInboxEnv(ws);
    } catch (e) {
      setError('Failed to save inbox environment settings.');
    } finally {
      setSavingEnv(false);
    }
  };

  const addWorkspace = async () => {
    const id = normalizeWorkspaceId(addDraft.id);
    if (!id) return;
    setSavingWorkspace(true);
    setError('');
    try {
      await api.post('/admin/workspaces', {
        id,
        label: String(addDraft.label || '').trim(),
        short: String(addDraft.short || '').trim(),
        copy_from: normalizeWorkspaceId(addDraft.copy_from),
      });
      const list = await loadWorkspaces();
      const next = normalizeWorkspaceId(id) || normalizeWorkspaceId(list?.[0]?.id);
      if (next) {
        try { localStorage.setItem('workspace', next); } catch {}
        setWorkspace(next);
      }
      setAddDraft({ id: '', label: '', short: '', copy_from: '' });
    } catch (e) {
      setError('Failed to add workspace.');
    } finally {
      setSavingWorkspace(false);
    }
  };

  if (!allowed && loading) return null;
  if (!allowed) return null;

  return (
    <div className="h-screen w-screen bg-white">
      <header className="h-12 px-3 flex items-center justify-between border-b bg-white/70 backdrop-blur sticky top-0 z-50">
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 text-sm bg-gray-800 text-white rounded" onClick={() => (window.location.href = '/#/automation-studio')}>
            Automation
          </button>
          <button className="px-3 py-1.5 text-sm bg-gray-200 text-gray-900 rounded border border-gray-300" onClick={() => (window.location.href = '/')}>
            Inbox
          </button>
          <div className="text-sm font-semibold text-gray-800 ml-2">Settings</div>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="border rounded px-2 py-1 text-sm"
            value={workspace}
            onChange={(e) => setWorkspace(normalizeWorkspaceId(e.target.value))}
          >
            {(workspaces || []).map((w) => (
              <option key={w.id} value={w.id}>{w.label || w.id}</option>
            ))}
          </select>
        </div>
      </header>

      <div className="p-4 max-w-6xl mx-auto">
        {error && <div className="mb-3 p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{error}</div>}
        {loading && <div className="text-sm text-slate-500">Loading…</div>}

        {!loading && (
          <div className="grid grid-cols-12 gap-4">
            {/* Left: workspace list + add */}
            <div className="col-span-12 md:col-span-4 space-y-3">
              <div className="border rounded bg-white">
                <div className="px-3 py-2 border-b text-sm font-medium">Workspaces</div>
                <div className="p-2 space-y-2">
                  {(workspaces || []).map((w) => (
                    <button
                      key={w.id}
                      type="button"
                      onClick={() => setWorkspace(w.id)}
                      className={`w-full px-3 py-2 rounded border text-left ${w.id === workspace ? 'border-blue-300 bg-blue-50' : 'border-slate-200 hover:bg-slate-50'}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="font-semibold text-sm truncate">{w.label || w.id}</div>
                        <div className="text-xs text-slate-500">{w.source || ''}</div>
                      </div>
                      <div className="text-xs text-slate-500 mt-1">id: <span className="font-mono">{w.id}</span> • short: <span className="font-mono">{w.short || ''}</span></div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="border rounded bg-white">
                <div className="px-3 py-2 border-b text-sm font-medium">Add workspace</div>
                <div className="p-3 space-y-2">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Workspace id (lowercase)</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-sm" value={addDraft.id} onChange={(e) => setAddDraft((d) => ({ ...d, id: e.target.value }))} placeholder="e.g. irramen" />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Label</div>
                      <input className="w-full border rounded px-2 py-1 text-sm" value={addDraft.label} onChange={(e) => setAddDraft((d) => ({ ...d, label: e.target.value }))} placeholder="e.g. MEN" />
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Short</div>
                      <input className="w-full border rounded px-2 py-1 text-sm" value={addDraft.short} onChange={(e) => setAddDraft((d) => ({ ...d, short: e.target.value }))} placeholder="e.g. MEN" />
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Copy settings from (optional)</div>
                    <select className="w-full border rounded px-2 py-1 text-sm" value={addDraft.copy_from} onChange={(e) => setAddDraft((d) => ({ ...d, copy_from: e.target.value }))}>
                      <option value="">— none —</option>
                      {(workspaces || []).map((w) => (
                        <option key={`copy:${w.id}`} value={w.id}>{w.label || w.id}</option>
                      ))}
                    </select>
                  </div>
                  <button
                    type="button"
                    className="w-full px-3 py-2 rounded bg-blue-600 text-white disabled:opacity-50"
                    disabled={savingWorkspace || !normalizeWorkspaceId(addDraft.id)}
                    onClick={addWorkspace}
                  >
                    {savingWorkspace ? 'Saving…' : 'Add workspace'}
                  </button>
                </div>
              </div>
            </div>

            {/* Right: settings */}
            <div className="col-span-12 md:col-span-8 space-y-3">
              <div className="border rounded bg-white">
                <div className="px-3 py-2 border-b text-sm font-medium">Workspace metadata</div>
                <div className="p-3 space-y-2">
                  <div className="text-xs text-slate-500">Workspace: <span className="font-mono">{workspace}</span></div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Label</div>
                      <input className="w-full border rounded px-2 py-1" value={wsLabelDraft} onChange={(e) => setWsLabelDraft(e.target.value)} />
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Short</div>
                      <input className="w-full border rounded px-2 py-1" value={wsShortDraft} onChange={(e) => setWsShortDraft(e.target.value)} />
                    </div>
                  </div>
                  <button type="button" className="px-3 py-1.5 rounded bg-gray-800 text-white disabled:opacity-50" disabled={savingWorkspace} onClick={saveWorkspaceMeta}>
                    {savingWorkspace ? 'Saving…' : 'Save workspace'}
                  </button>
                </div>
              </div>

              <div className="border rounded bg-white">
                <div className="px-3 py-2 border-b text-sm font-medium">Catalog buttons</div>
                <div className="p-3 space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="border rounded p-2">
                      <div className="text-xs font-semibold mb-2">Button A</div>
                      <div className="space-y-2">
                        <input className="w-full border rounded px-2 py-1" value={catalogFilters?.[0]?.label || ''} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[0]={...(n[0]||{}), label:e.target.value}; return n; })} placeholder="Label" />
                        <input className="w-full border rounded px-2 py-1" value={catalogFilters?.[0]?.query || ''} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[0]={...(n[0]||{}), query:e.target.value}; return n; })} placeholder="Query (match against set name/id)" />
                        <select className="w-full border rounded px-2 py-1" value={catalogFilters?.[0]?.match || 'includes'} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[0]={...(n[0]||{}), match:e.target.value}; return n; })}>
                          <option value="includes">includes</option>
                          <option value="startsWith">startsWith</option>
                        </select>
                      </div>
                    </div>
                    <div className="border rounded p-2">
                      <div className="text-xs font-semibold mb-2">Button B</div>
                      <div className="space-y-2">
                        <input className="w-full border rounded px-2 py-1" value={catalogFilters?.[1]?.label || ''} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[1]={...(n[1]||{}), label:e.target.value}; return n; })} placeholder="Label" />
                        <input className="w-full border rounded px-2 py-1" value={catalogFilters?.[1]?.query || ''} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[1]={...(n[1]||{}), query:e.target.value}; return n; })} placeholder="Query (match against set name/id)" />
                        <select className="w-full border rounded px-2 py-1" value={catalogFilters?.[1]?.match || 'includes'} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[1]={...(n[1]||{}), match:e.target.value}; return n; })}>
                          <option value="includes">includes</option>
                          <option value="startsWith">startsWith</option>
                        </select>
                      </div>
                    </div>
                    <div className="border rounded p-2 md:col-span-2">
                      <div className="text-xs font-semibold mb-2">All button</div>
                      <input className="w-full border rounded px-2 py-1" value={catalogFilters?.[2]?.label || ''} onChange={(e)=>setCatalogFilters((prev)=>{ const n=[...(prev||[])]; n[2]={...(n[2]||{}), label:e.target.value, type:'all'}; return n; })} placeholder="Label" />
                      <div className="text-[11px] text-slate-500 mt-1">Type is always <span className="font-mono">all</span>.</div>
                    </div>
                  </div>
                  <button type="button" className="px-3 py-1.5 rounded bg-blue-600 text-white disabled:opacity-50" disabled={savingCatalog} onClick={saveCatalog}>
                    {savingCatalog ? 'Saving…' : 'Save catalog buttons'}
                  </button>
                </div>
              </div>

              <div className="border rounded bg-white">
                <div className="px-3 py-2 border-b text-sm font-medium">Inbox environment (per workspace)</div>
                <div className="p-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Catalog ID</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={envDraft.catalog_id || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, catalog_id: e.target.value }))} />
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Phone Number ID (for this workspace inbox)</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={envDraft.phone_number_id || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, phone_number_id: e.target.value }))} />
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">WhatsApp Business Account ID (WABA ID)</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={envDraft.waba_id || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, waba_id: e.target.value }))} />
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">ALLOWED_PHONE_NUMBER_IDS (one per line)</div>
                    <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={4} value={envDraft.allowed_phone_number_ids || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, allowed_phone_number_ids: e.target.value }))} />
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">SURVEY_TEST_NUMBERS (digits only; one per line)</div>
                    <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={5} value={envDraft.survey_test_numbers || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, survey_test_numbers: e.target.value }))} />
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">AUTO_REPLY_TEST_NUMBERS (digits only; one per line)</div>
                    <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={5} value={envDraft.auto_reply_test_numbers || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, auto_reply_test_numbers: e.target.value }))} />
                  </div>
                  <div className="md:col-span-2">
                    <button type="button" className="px-3 py-1.5 rounded bg-gray-800 text-white disabled:opacity-50" disabled={savingEnv} onClick={saveEnv}>
                      {savingEnv ? 'Saving…' : 'Save inbox env'}
                    </button>
                  </div>
                </div>
              </div>

              {selectedWsObj?.source === 'env' && (
                <div className="text-xs text-slate-500">
                  Note: this workspace exists in env (<span className="font-mono">WORKSPACES</span>). Labels/buttons can be overridden here in DB, but WhatsApp credentials still come from env vars.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


