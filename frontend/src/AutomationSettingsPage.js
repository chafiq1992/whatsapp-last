import React, { useEffect, useMemo, useState } from 'react';
import api from './api';
import AnalyticsPanel from './AnalyticsPanel';
import AutomationStudio from './AutomationStudio';
import CustomersSegmentsPage from './CustomersSegmentsPage';
import WhatsAppTemplatesPanel from './WhatsAppTemplatesPanel';
import UsersTagsAdminPanel from './UsersTagsAdminPanel';
import { BarChart3, Bot, MessageSquareText, Users, Settings as SettingsIcon, BookOpen, Home, UserCog, Tag } from 'lucide-react';

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
  const [activeTab, setActiveTab] = useState('workspaces'); // analytics | automation | templates | customers | users_tags | workspaces | docs

  const [workspaces, setWorkspaces] = useState([]);
  const [defaultWorkspace, setDefaultWorkspace] = useState('irranova');
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
    meta_app_id: '',
    webhook_verify_token: '',
    access_token: '',
    access_token_present: false,
    access_token_hint: '',
    access_token_source: '',
  });
  const [savingEnv, setSavingEnv] = useState(false);

  const [shopifyDraft, setShopifyDraft] = useState({
    use_db_secret: false,
    secret: '',
    secret_present: false,
    secret_source: 'missing',
    secret_hint: '',
    webhook_path: '',
    webhook_url_example: '',
  });
  const [savingShopify, setSavingShopify] = useState(false);

  const selectedWsObj = useMemo(() => {
    const ws = normalizeWorkspaceId(workspace);
    return (workspaces || []).find((w) => normalizeWorkspaceId(w.id) === ws) || null;
  }, [workspaces, workspace]);

  const loadWorkspaces = async () => {
    const res = await api.get('/admin/workspaces');
    try {
      const def = normalizeWorkspaceId(res?.data?.default);
      if (def) setDefaultWorkspace(def);
    } catch {}
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
      meta_app_id: String(d.meta_app_id || ''),
      webhook_verify_token: '',
      access_token: '',
      access_token_present: Boolean(d.access_token_present),
      access_token_hint: String(d.access_token_hint || ''),
      access_token_source: String(d.access_token_source || ''),
    });
  };

  const loadShopifyWebhookAuth = async (ws) => {
    const res = await api.get('/admin/shopify-webhook-auth', { headers: { 'X-Workspace': normalizeWorkspaceId(ws) } });
    const d = res?.data || {};
    const useDb = String(d.secret_source || '') === 'db';
    setShopifyDraft((prev) => ({
      ...prev,
      use_db_secret: useDb,
      secret: '',
      secret_present: Boolean(d.secret_present),
      secret_source: String(d.secret_source || 'missing'),
      secret_hint: String(d.secret_hint || ''),
      webhook_path: String(d.webhook_path || ''),
      webhook_url_example: String(d.webhook_url_example || ''),
    }));
  };

  const refreshAllForWorkspace = async (ws) => {
    await Promise.allSettled([loadCatalogFilters(ws), loadInboxEnv(ws), loadShopifyWebhookAuth(ws)]);
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
        ...(envDraft.webhook_verify_token ? { webhook_verify_token: envDraft.webhook_verify_token } : {}),
        ...(envDraft.access_token ? { access_token: envDraft.access_token } : {}),
        ...(envDraft.access_token_source === 'env' ? { clear_access_token: true } : {}),
      }, { headers: { 'X-Workspace': ws } });
      await loadInboxEnv(ws);
    } catch (e) {
      setError('Failed to save inbox environment settings.');
    } finally {
      setSavingEnv(false);
    }
  };

  const saveShopify = async () => {
    const ws = normalizeWorkspaceId(workspace);
    if (!ws) return;
    setSavingShopify(true);
    setError('');
    try {
      if (shopifyDraft.use_db_secret) {
        await api.post(
          '/admin/shopify-webhook-auth',
          { ...(shopifyDraft.secret ? { secret: shopifyDraft.secret } : {}) },
          { headers: { 'X-Workspace': ws } }
        );
      } else {
        await api.post('/admin/shopify-webhook-auth', { clear_secret: true }, { headers: { 'X-Workspace': ws } });
      }
      await loadShopifyWebhookAuth(ws);
    } catch (e) {
      setError('Failed to save Shopify webhook authentication settings.');
    } finally {
      setSavingShopify(false);
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

  const deleteWorkspace = async () => {
    const ws = normalizeWorkspaceId(workspace);
    if (!ws) return;
    if (!selectedWsObj || String(selectedWsObj.source || '') !== 'db') {
      setError('Only DB workspaces can be deleted.');
      return;
    }
    if (ws === normalizeWorkspaceId(reservedDefaultWorkspace())) {
      setError('Cannot delete default workspace.');
      return;
    }
    const ok1 = window.confirm(`Delete workspace "${ws}" permanently?\n\nThis will remove it from the workspace list and delete its saved settings. This cannot be undone.`);
    if (!ok1) return;
    const ok2 = window.confirm(`Final confirmation:\n\nDelete "${ws}" now?`);
    if (!ok2) return;
    setSavingWorkspace(true);
    setError('');
    try {
      await api.delete(`/admin/workspaces/${encodeURIComponent(ws)}`);
      const list = await loadWorkspaces();
      const next = normalizeWorkspaceId(list?.[0]?.id) || 'irranova';
      try { localStorage.setItem('workspace', next); } catch {}
      setWorkspace(next);
    } catch (e) {
      setError('Failed to delete workspace.');
    } finally {
      setSavingWorkspace(false);
    }
  };

  function reservedDefaultWorkspace() {
    return defaultWorkspace || 'irranova';
  }

  const effectiveShopifyWebhookUrl = useMemo(() => {
    const ws = normalizeWorkspaceId(workspace) || 'irranova';
    const path = `/shopify/webhook/${ws}`;
    try {
      const origin = window.location.origin || '';
      if (origin) return `${origin}${path}`;
    } catch {}
    return (shopifyDraft.webhook_url_example || path);
  }, [workspace, shopifyDraft.webhook_url_example]);

  // WhatsApp templates (Meta)
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [templatesError, setTemplatesError] = useState('');
  const [templates, setTemplates] = useState([]);
  const loadTemplates = async () => {
    setTemplatesError('');
    setTemplatesLoading(true);
    try {
      const res = await api.get('/admin/whatsapp/templates');
      const arr = Array.isArray(res?.data?.templates) ? res.data.templates : [];
      setTemplates(arr);
    } catch {
      setTemplatesError('Failed to load WhatsApp templates. Check WABA ID + permissions.');
      setTemplates([]);
    } finally {
      setTemplatesLoading(false);
    }
  };

  const detectTabFromLocation = () => {
    try {
      const hash = String(window.location.hash || '');
      const path = String(window.location.pathname || '');
      const key = (hash || path).toLowerCase();
      // Prefer /settings/<tab>
      if (key.includes('/settings/analytics') || key.includes('/#/settings/analytics')) return 'analytics';
      if (key.includes('/settings/automation') || key.includes('/#/settings/automation') || key.includes('/automation-studio')) return 'automation';
      if (key.includes('/settings/templates') || key.includes('/#/settings/templates') || key.includes('/whatsapp-templates')) return 'templates';
      if (key.includes('/settings/customers') || key.includes('/#/settings/customers') || key.includes('/customers')) return 'customers';
      if (key.includes('/settings/users') || key.includes('/#/settings/users') || key.includes('/settings/tags') || key.includes('/#/settings/tags') || key.includes('/settings/users-tags') || key.includes('/#/settings/users-tags')) return 'users_tags';
      if (key.includes('/settings/docs') || key.includes('/#/settings/docs')) return 'docs';
      if (key.includes('/settings')) return 'workspaces';
      // Back-compat
      if (key.includes('/analytics')) return 'analytics';
      return 'workspaces';
    } catch {
      return 'workspaces';
    }
  };

  useEffect(() => {
    const apply = () => setActiveTab(detectTabFromLocation());
    apply();
    window.addEventListener('hashchange', apply);
    window.addEventListener('popstate', apply);
    return () => {
      window.removeEventListener('hashchange', apply);
      window.removeEventListener('popstate', apply);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const goTab = (tab) => {
    const t = String(tab || 'workspaces');
    setActiveTab(t);
    try {
      const next = t === 'workspaces' ? '/#/settings' : `/#/settings/${t === 'users_tags' ? 'users-tags' : t}`;
      window.location.hash = next.replace('/#', '#');
    } catch {}
  };

  useEffect(() => {
    // Lazy-load templates when needed
    if (activeTab !== 'templates') return;
    loadTemplates();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  if (!allowed && loading) return null;
  if (!allowed) return null;

  return (
    <div className="h-screen w-screen bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-sky-50 via-white to-indigo-50 text-slate-800">
      <header className="h-14 px-4 flex items-center justify-between border-b bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 text-white sticky top-0 z-50">
        {/* Left: Inbox */}
        <div className="flex items-center gap-2 min-w-[140px]">
          <button
            className="px-3 py-2 text-sm rounded-lg bg-white/10 hover:bg-white/15 border border-white/10 inline-flex items-center gap-2"
            onClick={() => (window.location.href = '/')}
          >
            <Home className="w-4 h-4" />
            Inbox
          </button>
        </div>

        {/* Middle: Tabs */}
        <div className="flex items-center justify-center flex-1">
          <div className="flex items-center gap-1 bg-white/10 border border-white/10 rounded-xl p-1">
            <button
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'analytics' ? 'bg-emerald-400/20 border border-emerald-300/20' : 'hover:bg-white/10'}`}
              onClick={() => goTab('analytics')}
            >
              <span className="inline-flex items-center gap-2"><BarChart3 className="w-4 h-4" />Analytics</span>
            </button>
            <button
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'automation' ? 'bg-blue-400/20 border border-blue-300/20' : 'hover:bg-white/10'}`}
              onClick={() => goTab('automation')}
            >
              <span className="inline-flex items-center gap-2"><Bot className="w-4 h-4" />Automation</span>
            </button>
            <button
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'templates' ? 'bg-sky-400/20 border border-sky-300/20' : 'hover:bg-white/10'}`}
              onClick={() => goTab('templates')}
            >
              <span className="inline-flex items-center gap-2"><MessageSquareText className="w-4 h-4" />WhatsApp Templates</span>
            </button>
            <button
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'customers' ? 'bg-purple-400/20 border border-purple-300/20' : 'hover:bg-white/10'}`}
              onClick={() => goTab('customers')}
            >
              <span className="inline-flex items-center gap-2"><Users className="w-4 h-4" />Customers</span>
            </button>
            <button
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'users_tags' ? 'bg-amber-400/20 border border-amber-300/20' : 'hover:bg-white/10'}`}
              onClick={() => goTab('users_tags')}
              title="Users & tags"
            >
              <span className="inline-flex items-center gap-2"><UserCog className="w-4 h-4" /><Tag className="w-4 h-4" />Users &amp; Tags</span>
            </button>
            <button
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'workspaces' ? 'bg-white text-slate-900 font-semibold shadow' : 'hover:bg-white/10'}`}
              onClick={() => goTab('workspaces')}
              title="Workspaces"
            >
              <span className="inline-flex items-center gap-2"><SettingsIcon className="w-4 h-4" />Workspaces</span>
            </button>
            <button
              type="button"
              className={`px-3 py-1.5 text-sm rounded-lg ${activeTab === 'docs' ? 'bg-indigo-400/30 border border-indigo-300/30' : 'hover:bg-white/10'}`}
              onClick={() => goTab('docs')}
              title="Docs"
            >
              <span className="inline-flex items-center gap-2"><BookOpen className="w-4 h-4" />Docs</span>
            </button>
          </div>
        </div>

        {/* Right: Workspace */}
        <div className="flex items-center justify-end gap-2 min-w-[240px]">
          <div className="hidden sm:block text-xs text-white/70">
            Workspace
          </div>
          <select
            className="bg-white/10 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-white"
            value={workspace}
            onChange={(e) => setWorkspace(normalizeWorkspaceId(e.target.value))}
            title="Selected workspace"
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

        {!loading && activeTab === 'analytics' && (
          <div className="rounded-2xl border border-slate-200 bg-white/70 backdrop-blur shadow-sm">
            <div className="p-4">
              <AnalyticsPanel key={String(workspace || 'irranova')} />
            </div>
          </div>
        )}

        {!loading && activeTab === 'automation' && (
          <div className="h-[calc(100vh-5rem)] border rounded-2xl overflow-hidden bg-white/50 backdrop-blur shadow-sm">
            <AutomationStudio embedded />
          </div>
        )}

        {!loading && activeTab === 'templates' && (
          <div className="h-[calc(100vh-5rem)] border rounded-2xl overflow-hidden bg-white/50 backdrop-blur shadow-sm">
            <div className="h-full overflow-auto">
              <WhatsAppTemplatesPanel templates={templates} loading={templatesLoading} error={templatesError} onRefresh={loadTemplates} />
            </div>
          </div>
        )}

        {!loading && activeTab === 'customers' && (
          <div className="h-[calc(100vh-5rem)] border rounded-2xl overflow-hidden bg-white/50 backdrop-blur shadow-sm">
            <CustomersSegmentsPage embedded />
          </div>
        )}

        {!loading && activeTab === 'docs' && (
          <div className="space-y-3">
            <div className="border rounded p-3 bg-slate-50">
              <div className="font-semibold mb-1">Shopify webhook URL (this workspace)</div>
              <div className="text-xs text-slate-600 mb-2">
                In Shopify Admin → Settings → Notifications → Webhooks, set the delivery URL to:
              </div>
              <div className="flex items-center gap-2">
                <input readOnly className="flex-1 border rounded px-2 py-1 font-mono text-xs bg-white" value={effectiveShopifyWebhookUrl} />
                <button
                  type="button"
                  className="px-2 py-1 rounded bg-gray-800 text-white"
                  onClick={() => {
                    try { navigator.clipboard.writeText(effectiveShopifyWebhookUrl); } catch {}
                  }}
                >
                  Copy
                </button>
              </div>
            </div>
            <div className="border rounded p-3">
              <div className="font-semibold mb-1">Webhook authentication (HMAC)</div>
              <div className="text-xs text-slate-600">
                Shopify signs the raw request body and sends the signature in <span className="font-mono">X-Shopify-Hmac-Sha256</span>.
                This app verifies it when a secret is configured.
              </div>
              <div className="mt-2 text-xs text-slate-700 space-y-1">
                <div><span className="font-semibold">Per-workspace env</span>: <span className="font-mono">SHOPIFY_WEBHOOK_SECRET_{String((normalizeWorkspaceId(workspace) || 'irranova')).toUpperCase()}</span></div>
                <div><span className="font-semibold">Global env fallback</span>: <span className="font-mono">SHOPIFY_WEBHOOK_SECRET</span></div>
                <div><span className="font-semibold">UI/DB override</span>: “Use DB secret” stores a secret per workspace and takes priority over env.</div>
              </div>
            </div>
            <div className="border rounded p-3">
              <div className="font-semibold mb-1">Topic-driven processing (X-Shopify-Topic)</div>
              <div className="text-xs text-slate-600">
                Shopify includes <span className="font-mono">X-Shopify-Topic</span> (example: <span className="font-mono">orders/paid</span>).
                Our automations match rules where <span className="font-mono">trigger.source=shopify</span> and <span className="font-mono">trigger.event</span> equals the topic exactly.
              </div>
            </div>
          </div>
        )}

        {!loading && activeTab === 'users_tags' && (
          <UsersTagsAdminPanel />
        )}

        {!loading && activeTab === 'workspaces' && (
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

                  <div className="pt-2 border-t">
                    <button
                      type="button"
                      className="inline-flex items-center gap-2 px-3 py-2 rounded bg-emerald-600 text-white hover:bg-emerald-700"
                      onClick={() => {
                        try {
                          const ws = normalizeWorkspaceId(workspace) || 'irranova';
                          const returnTo = '/#/settings?wa=connected';
                          window.location.href = `/admin/whatsapp/oauth/start?workspace=${encodeURIComponent(ws)}&return_to=${encodeURIComponent(returnTo)}`;
                        } catch {}
                      }}
                      title="Connect Meta WhatsApp (OAuth) and fetch WABA + Phone Number ID"
                    >
                      {/* Simple WhatsApp icon (inline SVG) */}
                      <svg viewBox="0 0 32 32" width="18" height="18" aria-hidden="true" focusable="false">
                        <path fill="currentColor" d="M19.11 17.46c-.3-.16-1.78-.88-2.06-.98-.28-.1-.49-.16-.7.16-.2.3-.8.98-.98 1.18-.18.2-.36.22-.66.06-.3-.16-1.28-.47-2.44-1.5-.9-.8-1.5-1.78-1.68-2.08-.18-.3-.02-.46.14-.62.14-.14.3-.36.46-.54.16-.18.2-.3.3-.5.1-.2.04-.38-.02-.54-.06-.16-.7-1.68-.96-2.3-.26-.62-.52-.54-.7-.54h-.6c-.2 0-.54.08-.82.38-.28.3-1.08 1.06-1.08 2.6s1.1 3.02 1.26 3.22c.16.2 2.16 3.3 5.24 4.62.74.32 1.32.5 1.78.64.74.24 1.42.2 1.96.12.6-.1 1.78-.72 2.04-1.42.26-.7.26-1.3.18-1.42-.08-.12-.28-.2-.58-.36z"/>
                        <path fill="currentColor" d="M16 3C9.38 3 4 8.38 4 15c0 2.04.52 4 1.5 5.74L4 29l8.46-1.46A11.9 11.9 0 0 0 16 27c6.62 0 12-5.38 12-12S22.62 3 16 3zm0 21.5c-1.66 0-3.28-.44-4.7-1.28l-.34-.2-5.02.86.9-4.9-.22-.36A9.4 9.4 0 0 1 6.6 15c0-5.18 4.22-9.4 9.4-9.4s9.4 4.22 9.4 9.4-4.22 9.4-9.4 9.4z"/>
                      </svg>
                      Connect WhatsApp
                    </button>
                    <div className="text-[11px] text-slate-500 mt-1">
                      This will connect the client’s Meta Business and auto-fill <span className="font-mono">WABA ID</span>, <span className="font-mono">Phone Number ID</span>, and store the token for this workspace.
                    </div>
                  </div>
                  {selectedWsObj?.source === 'db' && normalizeWorkspaceId(workspace) !== normalizeWorkspaceId(reservedDefaultWorkspace()) && (
                    <div className="pt-2 border-t">
                      <button
                        type="button"
                        className="px-3 py-1.5 rounded bg-rose-600 text-white disabled:opacity-50"
                        disabled={savingWorkspace}
                        onClick={deleteWorkspace}
                        title="Permanently delete this workspace"
                      >
                        {savingWorkspace ? 'Working…' : 'Delete workspace'}
                      </button>
                      <div className="text-[11px] text-rose-700 mt-1">Warning: this is permanent.</div>
                    </div>
                  )}
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
                    <div className="text-xs text-slate-500 mb-1">WhatsApp Access Token</div>
                    <div className="flex items-center gap-2 mb-2">
                      <label className="text-xs text-slate-600 flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={String(envDraft.access_token_source || 'env') === 'env'}
                          onChange={(e) => {
                            const useEnv = !!e.target.checked;
                            setEnvDraft((d) => ({
                              ...d,
                              access_token: '',
                              access_token_source: useEnv ? 'env' : 'db',
                            }));
                          }}
                        />
                        Use Cloud Run secret token (recommended)
                      </label>
                      <span className="text-[11px] text-slate-500">
                        Current: <span className="font-mono">{envDraft.access_token_source || 'env'}</span>
                        {envDraft.access_token_hint ? <> • …{envDraft.access_token_hint}</> : null}
                      </span>
                    </div>
                    <input
                      type="password"
                      className="w-full border rounded px-2 py-1 font-mono text-xs"
                      value={envDraft.access_token || ''}
                      onChange={(e)=>setEnvDraft((d)=>({ ...d, access_token: e.target.value }))}
                      disabled={String(envDraft.access_token_source || 'env') === 'env'}
                      placeholder={
                        String(envDraft.access_token_source || 'env') === 'env'
                          ? 'Using Cloud Run secret token'
                          : (envDraft.access_token_present ? `Saved (…${envDraft.access_token_hint || ''}) — leave blank to keep` : 'Paste token here')
                      }
                    />
                    <div className="text-[11px] text-slate-500 mt-1">
                      {String(envDraft.access_token_source || 'env') === 'env'
                        ? 'Token comes from Cloud Run secret env; not stored in DB.'
                        : (envDraft.access_token_present ? 'Token is stored in DB. Leave empty to keep it unchanged.' : 'Required for this workspace to send WhatsApp messages.')}
                    </div>
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Catalog ID</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={envDraft.catalog_id || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, catalog_id: e.target.value }))} />
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Phone Number ID (for this workspace inbox)</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={envDraft.phone_number_id || ''} onChange={(e)=>setEnvDraft((d)=>({ ...d, phone_number_id: e.target.value }))} />
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Meta App ID (global; from server env)</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs bg-slate-50" value={envDraft.meta_app_id || ''} readOnly />
                    <div className="text-[11px] text-slate-500 mt-1">
                      This should be the same Meta App for all workspaces/clients. Configure it in Cloud Run env (<span className="font-mono">META_APP_ID</span>/<span className="font-mono">META_APP_SECRET</span>).
                    </div>
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-xs text-slate-500 mb-1">Webhook Verify Token (optional)</div>
                    <input
                      type="password"
                      className="w-full border rounded px-2 py-1 font-mono text-xs"
                      value={envDraft.webhook_verify_token || ''}
                      onChange={(e)=>setEnvDraft((d)=>({ ...d, webhook_verify_token: e.target.value }))}
                      placeholder="Leave empty to keep current"
                    />
                    <div className="text-[11px] text-slate-500 mt-1">
                      Meta verification uses a single token for the webhook URL. This is optional; you can keep using the Cloud Run env token.
                    </div>
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

              <div className="border rounded bg-white">
                <div className="px-3 py-2 border-b text-sm font-medium flex items-center justify-between">
                  <span>Shopify webhooks (per workspace)</span>
                  <button type="button" className="text-xs px-2 py-1 rounded border bg-white hover:bg-slate-50" onClick={() => goTab('docs')}>
                    Docs
                  </button>
                </div>
                <div className="p-3 space-y-3">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Webhook URL for this workspace</div>
                    <div className="flex items-center gap-2">
                      <input readOnly className="flex-1 border rounded px-2 py-1 font-mono text-xs bg-slate-50" value={effectiveShopifyWebhookUrl} />
                      <button
                        type="button"
                        className="px-2 py-1 rounded bg-gray-800 text-white"
                        onClick={() => {
                          try { navigator.clipboard.writeText(effectiveShopifyWebhookUrl); } catch {}
                        }}
                      >
                        Copy
                      </button>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      Shopify topics come in <span className="font-mono">X-Shopify-Topic</span> and automations match <span className="font-mono">trigger.event</span> exactly.
                    </div>
                  </div>

                  <div>
                    <div className="text-xs text-slate-500 mb-1">Webhook secret (HMAC)</div>
                    <div className="flex items-center gap-2 mb-2">
                      <label className="text-xs text-slate-600 flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={Boolean(shopifyDraft.use_db_secret)}
                          onChange={(e) => {
                            const useDb = !!e.target.checked;
                            setShopifyDraft((d) => ({ ...d, use_db_secret: useDb, secret: '' }));
                          }}
                        />
                        Use DB secret (set from UI)
                      </label>
                      <span className="text-[11px] text-slate-500">
                        Current: <span className="font-mono">{shopifyDraft.secret_source || 'missing'}</span>
                        {shopifyDraft.secret_hint ? <> • …{shopifyDraft.secret_hint}</> : null}
                      </span>
                    </div>
                    <input
                      type="password"
                      className="w-full border rounded px-2 py-1 font-mono text-xs"
                      value={shopifyDraft.secret || ''}
                      onChange={(e) => setShopifyDraft((d) => ({ ...d, secret: e.target.value }))}
                      disabled={!shopifyDraft.use_db_secret}
                      placeholder={
                        shopifyDraft.use_db_secret
                          ? (shopifyDraft.secret_present && shopifyDraft.secret_source === 'db' ? 'Saved in DB — leave blank to keep' : 'Paste Shopify webhook secret here')
                          : 'Using env secret (SHOPIFY_WEBHOOK_SECRET_<WORKSPACE> or SHOPIFY_WEBHOOK_SECRET)'
                      }
                    />
                    <div className="text-[11px] text-slate-500 mt-1">
                      {shopifyDraft.use_db_secret
                        ? 'DB secret takes priority over env. Leave empty to keep the existing DB secret.'
                        : 'Env secret is recommended for production; switching off DB secret will delete the DB override for this workspace.'}
                    </div>
                  </div>

                  <div>
                    <button
                      type="button"
                      className="px-3 py-1.5 rounded bg-gray-800 text-white disabled:opacity-50"
                      disabled={savingShopify}
                      onClick={saveShopify}
                    >
                      {savingShopify ? 'Saving…' : 'Save Shopify webhook auth'}
                    </button>
                  </div>
                </div>
              </div>

              {selectedWsObj?.source === 'env' && (
                <div className="text-xs text-slate-500">
                  Note: this workspace exists in env (<span className="font-mono">WORKSPACES</span>). You can still override WhatsApp credentials per workspace here in DB (recommended to avoid redeploys).
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


