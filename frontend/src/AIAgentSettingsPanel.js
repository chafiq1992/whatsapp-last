import React, { useEffect, useMemo, useState } from 'react';
import api from './api';

const DEFAULT_FORM = {
  enabled: false,
  run_mode: 'shadow',
  model: 'gpt-5.1',
  api_base: 'https://api.openai.com/v1',
  max_output_tokens: 900,
  max_context_messages: 12,
  catalog_results_limit: 6,
  send_catalog_when_possible: true,
  handoff_enabled: true,
  handoff_on_human_request: true,
  low_confidence_threshold: 0.58,
  anger_handoff_threshold: 'frustrated',
  autonomous_eval_gate_enabled: true,
  autonomous_min_fixture_pass_rate: 0.75,
  autonomous_require_recent_fixture_eval_hours: 72,
  test_numbers: '',
  supported_languages: 'darija, ar, fr, en',
  instructions: '',
  business_context: '',
  openai_api_key: '',
  clear_openai_api_key: false,
  openai_api_key_present: false,
  openai_api_key_hint: '',
};

const DEFAULT_POLICY = {
  id: '',
  topic: 'delivery',
  locale: 'fr',
  title: '',
  content: '',
  status: 'approved',
  version: '1',
};

export default function AIAgentSettingsPanel({ workspace }) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [form, setForm] = useState(DEFAULT_FORM);
  const [policies, setPolicies] = useState([]);
  const [policyDraft, setPolicyDraft] = useState(DEFAULT_POLICY);
  const [policySaving, setPolicySaving] = useState(false);
  const [turns, setTurns] = useState([]);
  const [evalRuns, setEvalRuns] = useState([]);
  const [evalRunning, setEvalRunning] = useState(false);
  const [selectedEvalRun, setSelectedEvalRun] = useState(null);
  const [gateStatus, setGateStatus] = useState(null);
  const [runTypeFilter, setRunTypeFilter] = useState('all');
  const [runStatusFilter, setRunStatusFilter] = useState('all');
  const [compareRunId, setCompareRunId] = useState('');
  const [compareSummary, setCompareSummary] = useState(null);

  const wsHeader = useMemo(() => ({ 'X-Workspace': workspace }), [workspace]);

  const loadAll = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const [cfgRes, policyRes, turnsRes, evalRunsRes, gateRes] = await Promise.all([
        api.get('/admin/ai-agent/config', { headers: wsHeader }),
        api.get('/admin/ai-agent/policies', { headers: wsHeader }),
        api.get('/admin/ai-agent/turns?limit=20', { headers: wsHeader }),
        api.get('/admin/ai-agent/evals/runs?limit=25', { headers: wsHeader }),
        api.get('/admin/ai-agent/evals/gate-status', { headers: wsHeader }),
      ]);
      const cfg = cfgRes?.data?.config || {};
      setForm({
        ...DEFAULT_FORM,
        ...cfg,
        test_numbers: Array.isArray(cfg?.test_numbers) ? cfg.test_numbers.join('\n') : '',
        supported_languages: Array.isArray(cfg?.supported_languages) ? cfg.supported_languages.join(', ') : DEFAULT_FORM.supported_languages,
        openai_api_key: '',
        clear_openai_api_key: false,
        openai_api_key_present: Boolean(cfg?.openai_api_key_present),
        openai_api_key_hint: String(cfg?.openai_api_key_hint || ''),
      });
      setPolicies(Array.isArray(policyRes?.data?.items) ? policyRes.data.items : []);
      setTurns(Array.isArray(turnsRes?.data?.items) ? turnsRes.data.items : []);
      setEvalRuns(Array.isArray(evalRunsRes?.data?.items) ? evalRunsRes.data.items : []);
      setGateStatus(gateRes?.data?.item || null);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to load AI agent settings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace]);

  const updateForm = (patch) => setForm((prev) => ({ ...prev, ...patch }));

  const saveConfig = async () => {
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const payload = {
        enabled: !!form.enabled,
        run_mode: form.run_mode,
        model: form.model,
        api_base: form.api_base,
        max_output_tokens: Number(form.max_output_tokens || 900),
        max_context_messages: Number(form.max_context_messages || 12),
        catalog_results_limit: Number(form.catalog_results_limit || 6),
        send_catalog_when_possible: !!form.send_catalog_when_possible,
        handoff_enabled: !!form.handoff_enabled,
        handoff_on_human_request: !!form.handoff_on_human_request,
        low_confidence_threshold: Number(form.low_confidence_threshold || 0.58),
        anger_handoff_threshold: form.anger_handoff_threshold,
        autonomous_eval_gate_enabled: !!form.autonomous_eval_gate_enabled,
        autonomous_min_fixture_pass_rate: Number(form.autonomous_min_fixture_pass_rate || 0.75),
        autonomous_require_recent_fixture_eval_hours: Number(form.autonomous_require_recent_fixture_eval_hours || 72),
        test_numbers: String(form.test_numbers || '')
          .split(/\r?\n|,|;/)
          .map((x) => String(x || '').trim())
          .filter(Boolean),
        supported_languages: String(form.supported_languages || '')
          .split(',')
          .map((x) => String(x || '').trim())
          .filter(Boolean),
        instructions: form.instructions,
        business_context: form.business_context,
        openai_api_key: String(form.openai_api_key || '').trim(),
        clear_openai_api_key: !!form.clear_openai_api_key,
      };
      const res = await api.post('/admin/ai-agent/config', payload, { headers: wsHeader });
      const cfg = res?.data?.config || {};
      setForm((prev) => ({
        ...prev,
        openai_api_key: '',
        clear_openai_api_key: false,
        openai_api_key_present: Boolean(cfg?.openai_api_key_present),
        openai_api_key_hint: String(cfg?.openai_api_key_hint || ''),
      }));
      setSuccess('AI agent settings saved.');
      await loadAll();
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to save AI agent settings.');
    } finally {
      setSaving(false);
    }
  };

  const savePolicy = async () => {
    setPolicySaving(true);
    setError('');
    setSuccess('');
    try {
      await api.post('/admin/ai-agent/policies', policyDraft, { headers: wsHeader });
      setPolicyDraft(DEFAULT_POLICY);
      setSuccess('Policy saved.');
      await loadAll();
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to save policy.');
    } finally {
      setPolicySaving(false);
    }
  };

  const editPolicy = (item) => {
    setPolicyDraft({
      id: item?.id || '',
      topic: item?.topic || 'delivery',
      locale: item?.locale || 'fr',
      title: item?.title || '',
      content: item?.content || '',
      status: item?.status || 'approved',
      version: item?.version || '1',
    });
  };

  const deletePolicy = async (id) => {
    try {
      await api.delete(`/admin/ai-agent/policies/${encodeURIComponent(id)}`, { headers: wsHeader });
      setSuccess('Policy deleted.');
      await loadAll();
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to delete policy.');
    }
  };

  const runEval = async (kind) => {
    setEvalRunning(true);
    setError('');
    setSuccess('');
    try {
      const endpoint = kind === 'fixture' ? '/admin/ai-agent/evals/fixture-run' : '/admin/ai-agent/evals/replay-run';
      const payload = kind === 'fixture'
        ? { label: `Fixture eval ${new Date().toISOString()}` }
        : { label: `Replay eval ${new Date().toISOString()}`, limit: 10, transcript_messages: 12 };
      const res = await api.post(endpoint, payload, { headers: wsHeader });
      setSelectedEvalRun(res?.data?.item || null);
      setSuccess(kind === 'fixture' ? 'Fixture eval completed.' : 'Replay eval completed.');
      await loadAll();
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to run eval.');
    } finally {
      setEvalRunning(false);
    }
  };

  const loadEvalRun = async (runId) => {
    try {
      const res = await api.get(`/admin/ai-agent/evals/runs/${encodeURIComponent(runId)}`, { headers: wsHeader });
      setSelectedEvalRun(res?.data?.item || null);
      setCompareSummary(null);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || 'Failed to load eval run.');
    }
  };

  useEffect(() => {
    const loadCompare = async () => {
      if (!selectedEvalRun?.id || !compareRunId) {
        setCompareSummary(null);
        return;
      }
      try {
        const res = await api.get(
          `/admin/ai-agent/evals/compare?left_run_id=${encodeURIComponent(selectedEvalRun.id)}&right_run_id=${encodeURIComponent(compareRunId)}`,
          { headers: wsHeader },
        );
        setCompareSummary(res?.data?.item || null);
      } catch (e) {
        setError(e?.response?.data?.detail || e?.message || 'Failed to compare eval runs.');
      }
    };
    loadCompare();
  }, [compareRunId, selectedEvalRun?.id, wsHeader]);

  const filteredEvalRuns = useMemo(() => (
    (evalRuns || []).filter((run) => {
      const runTypeOk = runTypeFilter === 'all' || String(run?.run_type || '') === runTypeFilter;
      const statusOk = runStatusFilter === 'all' || String(run?.status || '') === runStatusFilter;
      return runTypeOk && statusOk;
    })
  ), [evalRuns, runStatusFilter, runTypeFilter]);

  const gateTone = gateStatus?.enabled
    ? (gateStatus?.blocking ? 'rose' : 'emerald')
    : 'amber';

  if (loading) {
    return <div className="p-4 text-sm text-slate-500">Loading AI agent settings...</div>;
  }

  return (
    <div className="space-y-4">
      {error ? <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div> : null}
      {success ? <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">{success}</div> : null}

      <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 shadow-sm">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-lg font-semibold text-slate-900">AI Agent</div>
            <div className="mt-1 text-sm text-slate-600">
              Configure the customer-service AI for this workspace. `shadow` logs decisions only, `suggest` prepares the stack for assisted mode, and `autonomous` lets the agent reply directly.
            </div>
          </div>
          <button
            type="button"
            onClick={saveConfig}
            disabled={saving}
            className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
          >
            {saving ? 'Saving...' : 'Save AI Settings'}
          </button>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
          <label className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
            <div className="font-medium text-slate-800">Enable AI agent</div>
            <div className="mt-1 text-xs text-slate-500">Turns the customer-service runtime on for inbound WhatsApp text messages.</div>
            <input className="mt-3 h-4 w-4" type="checkbox" checked={!!form.enabled} onChange={(e) => updateForm({ enabled: e.target.checked })} />
          </label>

          <label className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
            <div className="font-medium text-slate-800">Run mode</div>
            <select className="mt-3 w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={form.run_mode} onChange={(e) => updateForm({ run_mode: e.target.value })}>
              <option value="shadow">Shadow</option>
              <option value="suggest">Suggest</option>
              <option value="autonomous">Autonomous</option>
            </select>
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">OpenAI API key</div>
            <input
              className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2"
              type="password"
              placeholder={form.openai_api_key_present ? `Stored key ending in ${form.openai_api_key_hint || '****'}` : 'sk-...'}
              value={form.openai_api_key}
              onChange={(e) => updateForm({ openai_api_key: e.target.value, clear_openai_api_key: false })}
            />
            <label className="mt-2 flex items-center gap-2 text-xs text-slate-600">
              <input type="checkbox" checked={!!form.clear_openai_api_key} onChange={(e) => updateForm({ clear_openai_api_key: e.target.checked, openai_api_key: e.target.checked ? '' : form.openai_api_key })} />
              Clear stored key for this workspace
            </label>
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Model</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={form.model} onChange={(e) => updateForm({ model: e.target.value })} />
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">API base</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={form.api_base} onChange={(e) => updateForm({ api_base: e.target.value })} />
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Supported languages</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={form.supported_languages} onChange={(e) => updateForm({ supported_languages: e.target.value })} />
          </label>

          <label className="text-sm md:col-span-2">
            <div className="mb-1 font-medium text-slate-800">Test numbers only</div>
            <textarea
              className="min-h-[110px] w-full rounded-xl border border-slate-300 bg-white px-3 py-3 text-sm"
              value={form.test_numbers}
              onChange={(e) => updateForm({ test_numbers: e.target.value })}
              placeholder={'+212600000000\n+212611111111'}
            />
            <div className="mt-2 text-xs text-slate-500">
              Add one WhatsApp number per line, or separate them with commas. While this list has numbers, the AI agent will only run for those conversations. Leave it empty to activate the AI for all customers.
            </div>
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Max output tokens</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" type="number" value={form.max_output_tokens} onChange={(e) => updateForm({ max_output_tokens: e.target.value })} />
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Context messages</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" type="number" value={form.max_context_messages} onChange={(e) => updateForm({ max_context_messages: e.target.value })} />
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Catalog results limit</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" type="number" value={form.catalog_results_limit} onChange={(e) => updateForm({ catalog_results_limit: e.target.value })} />
          </label>

          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Low-confidence handoff threshold</div>
            <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" type="number" step="0.01" min="0" max="1" value={form.low_confidence_threshold} onChange={(e) => updateForm({ low_confidence_threshold: e.target.value })} />
          </label>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
          <label className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <input type="checkbox" checked={!!form.send_catalog_when_possible} onChange={(e) => updateForm({ send_catalog_when_possible: e.target.checked })} />
            Send catalog products when the AI has strong matches
          </label>
          <label className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <input type="checkbox" checked={!!form.handoff_enabled} onChange={(e) => updateForm({ handoff_enabled: e.target.checked })} />
            Allow AI to trigger human handoff
          </label>
          <label className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <input type="checkbox" checked={!!form.handoff_on_human_request} onChange={(e) => updateForm({ handoff_on_human_request: e.target.checked })} />
            Handoff when the customer explicitly asks for a human
          </label>
        </div>

        <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-sm font-semibold text-slate-900">Autonomous safety gate</div>
              <div className="mt-1 text-xs text-slate-600">
                Keep live autonomous replies blocked until a recent fixture eval meets the configured quality threshold.
              </div>
            </div>
            <div className={`rounded-full px-3 py-1 text-xs font-medium ${gateTone === 'emerald' ? 'bg-emerald-100 text-emerald-700' : gateTone === 'rose' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700'}`}>
              {gateStatus?.enabled ? (gateStatus?.blocking ? 'Blocked' : 'Ready') : 'Disabled'}
            </div>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
            <label className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <input type="checkbox" checked={!!form.autonomous_eval_gate_enabled} onChange={(e) => updateForm({ autonomous_eval_gate_enabled: e.target.checked })} />
              Require fixture eval before autonomous replies
            </label>
            <label className="text-sm">
              <div className="mb-1 font-medium text-slate-800">Minimum fixture pass rate</div>
              <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" type="number" step="0.01" min="0" max="1" value={form.autonomous_min_fixture_pass_rate} onChange={(e) => updateForm({ autonomous_min_fixture_pass_rate: e.target.value })} />
            </label>
            <label className="text-sm">
              <div className="mb-1 font-medium text-slate-800">Fixture freshness window (hours)</div>
              <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" type="number" min="1" value={form.autonomous_require_recent_fixture_eval_hours} onChange={(e) => updateForm({ autonomous_require_recent_fixture_eval_hours: e.target.value })} />
            </label>
          </div>

          {gateStatus ? (
            <div className={`mt-4 rounded-xl border px-4 py-3 text-sm ${gateTone === 'emerald' ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : gateTone === 'rose' ? 'border-rose-200 bg-rose-50 text-rose-800' : 'border-amber-200 bg-amber-50 text-amber-800'}`}>
              <div className="font-medium">{gateStatus.message}</div>
              <div className="mt-2 grid grid-cols-1 gap-2 text-xs md:grid-cols-4">
                <div>Latest fixture run: <span className="font-semibold">{gateStatus.latest_run_id ? `#${gateStatus.latest_run_id}` : 'none'}</span></div>
                <div>Pass rate: <span className="font-semibold">{gateStatus.latest_pass_rate ?? 'n/a'}</span></div>
                <div>Threshold: <span className="font-semibold">{gateStatus.threshold ?? 'n/a'}</span></div>
                <div>Age (hours): <span className="font-semibold">{gateStatus.age_hours ?? 'n/a'}</span></div>
              </div>
            </div>
          ) : null}
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4">
          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Agent instructions</div>
            <textarea className="min-h-[150px] w-full rounded-xl border border-slate-300 bg-white px-3 py-3 font-mono text-xs" value={form.instructions} onChange={(e) => updateForm({ instructions: e.target.value })} />
          </label>
          <label className="text-sm">
            <div className="mb-1 font-medium text-slate-800">Business context</div>
            <textarea className="min-h-[110px] w-full rounded-xl border border-slate-300 bg-white px-3 py-3 font-mono text-xs" value={form.business_context} onChange={(e) => updateForm({ business_context: e.target.value })} />
          </label>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 shadow-sm">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-lg font-semibold text-slate-900">Approved policy snippets</div>
              <div className="mt-1 text-sm text-slate-600">Only approved policies should be used for delivery, COD, exchange, return, complaint, and refund answers.</div>
            </div>
            <button type="button" onClick={savePolicy} disabled={policySaving} className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60">
              {policySaving ? 'Saving...' : 'Save Policy'}
            </button>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <label className="text-sm">
              <div className="mb-1 font-medium text-slate-800">Topic</div>
              <select className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={policyDraft.topic} onChange={(e) => setPolicyDraft((prev) => ({ ...prev, topic: e.target.value }))}>
                <option value="delivery">Delivery</option>
                <option value="cod">COD</option>
                <option value="exchange">Exchange</option>
                <option value="return">Return</option>
                <option value="refund">Refund</option>
                <option value="complaint">Complaint</option>
              </select>
            </label>
            <label className="text-sm">
              <div className="mb-1 font-medium text-slate-800">Locale</div>
              <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={policyDraft.locale} onChange={(e) => setPolicyDraft((prev) => ({ ...prev, locale: e.target.value }))} />
            </label>
            <label className="text-sm md:col-span-2">
              <div className="mb-1 font-medium text-slate-800">Title</div>
              <input className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={policyDraft.title} onChange={(e) => setPolicyDraft((prev) => ({ ...prev, title: e.target.value }))} />
            </label>
            <label className="text-sm md:col-span-2">
              <div className="mb-1 font-medium text-slate-800">Approved answer / policy text</div>
              <textarea className="min-h-[130px] w-full rounded-xl border border-slate-300 bg-white px-3 py-3" value={policyDraft.content} onChange={(e) => setPolicyDraft((prev) => ({ ...prev, content: e.target.value }))} />
            </label>
          </div>

          <div className="mt-5 space-y-3">
            {policies.length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-500">No policy snippets saved yet for this workspace.</div> : null}
            {policies.map((item) => (
              <div key={item.id} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-semibold text-slate-900">{item.title}</div>
                    <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">{item.topic} / {item.locale}</div>
                    <div className="mt-2 whitespace-pre-wrap text-sm text-slate-700">{item.content}</div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <button type="button" onClick={() => editPolicy(item)} className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs text-slate-700 hover:bg-white">Edit</button>
                    <button type="button" onClick={() => deletePolicy(item.id)} className="rounded-lg border border-rose-300 px-3 py-1.5 text-xs text-rose-700 hover:bg-rose-50">Delete</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 shadow-sm">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-lg font-semibold text-slate-900">Recent AI turns</div>
              <div className="mt-1 text-sm text-slate-600">Latest decision logs for this workspace. This is especially useful while the agent is in shadow mode.</div>
            </div>
            <button type="button" onClick={loadAll} className="rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50">Refresh</button>
          </div>

          <div className="mt-4 space-y-3">
            {turns.length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-500">No AI turns logged yet.</div> : null}
            {turns.map((turn) => (
              <div key={turn.id} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <div className="text-sm font-semibold text-slate-900">#{turn.id} - {turn.user_id}</div>
                    <div className="mt-1 text-xs text-slate-500">{turn.created_at} - {turn.turn_mode} - {turn.turn_status}</div>
                  </div>
                  <div className="rounded-full bg-slate-900 px-3 py-1 text-xs font-medium text-white">{turn.action || 'none'}</div>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-600">
                  <div>Intent: <span className="font-medium text-slate-800">{turn.detected_intent || 'n/a'}</span></div>
                  <div>Language: <span className="font-medium text-slate-800">{turn.detected_language || 'n/a'}</span></div>
                  <div>Emotion: <span className="font-medium text-slate-800">{turn.emotion || 'n/a'}</span></div>
                  <div>Confidence: <span className="font-medium text-slate-800">{turn.confidence ?? 'n/a'}</span></div>
                </div>
                {turn.reply_text ? <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700">{turn.reply_text}</div> : null}
                {turn.error_text ? <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700">{turn.error_text}</div> : null}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[0.8fr_1.2fr]">
        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 shadow-sm">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-lg font-semibold text-slate-900">Replay & evals</div>
              <div className="mt-1 text-sm text-slate-600">Run fixed benchmark cases or replay recent inbox conversations in safe shadow mode.</div>
            </div>
            <button type="button" onClick={loadAll} className="rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50">Refresh</button>
          </div>

          <div className="mt-4 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => runEval('fixture')}
              disabled={evalRunning}
              className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
            >
              {evalRunning ? 'Running...' : 'Run Fixture Eval'}
            </button>
            <button
              type="button"
              onClick={() => runEval('replay')}
              disabled={evalRunning}
              className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-60"
            >
              {evalRunning ? 'Running...' : 'Run Replay Eval'}
            </button>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="text-sm">
              <div className="mb-1 font-medium text-slate-800">Run type filter</div>
              <select className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={runTypeFilter} onChange={(e) => setRunTypeFilter(e.target.value)}>
                <option value="all">All run types</option>
                <option value="fixture">Fixture</option>
                <option value="replay">Replay</option>
              </select>
            </label>
            <label className="text-sm">
              <div className="mb-1 font-medium text-slate-800">Status filter</div>
              <select className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2" value={runStatusFilter} onChange={(e) => setRunStatusFilter(e.target.value)}>
                <option value="all">All statuses</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="running">Running</option>
              </select>
            </label>
          </div>

          <div className="mt-5 space-y-3">
            {filteredEvalRuns.length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-500">No eval runs match the current filters.</div> : null}
            {filteredEvalRuns.map((run) => (
              <button
                key={run.id}
                type="button"
                onClick={() => {
                  loadEvalRun(run.id);
                  setCompareRunId('');
                }}
                className={`block w-full rounded-xl border px-4 py-3 text-left hover:bg-white ${selectedEvalRun?.id === run.id ? 'border-slate-900 bg-white' : 'border-slate-200 bg-slate-50'}`}
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-slate-900">#{run.id} - {run.run_type}</div>
                    <div className="mt-1 text-xs text-slate-500">{run.created_at} - {run.model || 'n/a'} - {run.status}</div>
                  </div>
                  <div className="rounded-full bg-slate-900 px-3 py-1 text-xs font-medium text-white">{run.sample_size || 0}</div>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 shadow-sm">
          <div className="text-lg font-semibold text-slate-900">Selected eval run</div>
          <div className="mt-1 text-sm text-slate-600">Inspect pass rate, replay outputs, and tool usage for the selected run.</div>

          {!selectedEvalRun ? (
            <div className="mt-4 rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-500">
              Select an eval run to inspect its details.
            </div>
          ) : (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Run</div>
                  <div className="mt-1 font-semibold text-slate-900">#{selectedEvalRun.id}</div>
                </div>
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Type</div>
                  <div className="mt-1 font-semibold text-slate-900">{selectedEvalRun.run_type}</div>
                </div>
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Status</div>
                  <div className="mt-1 font-semibold text-slate-900">{selectedEvalRun.status}</div>
                </div>
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Sample size</div>
                  <div className="mt-1 font-semibold text-slate-900">{selectedEvalRun.sample_size || 0}</div>
                </div>
              </div>

              <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <div className="text-sm font-semibold text-slate-900">Compare against another run</div>
                <div className="mt-1 text-xs text-slate-600">Compare pass rate changes, handoff drift, and case-level behavior between two runs.</div>
                <select className="mt-3 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm" value={compareRunId} onChange={(e) => setCompareRunId(e.target.value)}>
                  <option value="">Select another eval run</option>
                  {(evalRuns || []).filter((run) => run.id !== selectedEvalRun.id).map((run) => (
                    <option key={run.id} value={run.id}>
                      #{run.id} - {run.run_type} - {run.created_at}
                    </option>
                  ))}
                </select>
              </div>

              {compareSummary ? (
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="text-sm font-semibold text-slate-900">Run comparison</div>
                  <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
                    {Object.entries(compareSummary.summary_delta || {}).map(([key, value]) => (
                      <div key={key} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                        <div className="font-medium text-slate-900">{key}</div>
                        <div className="mt-1">Left: {value?.left ?? 'n/a'}</div>
                        <div>Right: {value?.right ?? 'n/a'}</div>
                        <div className="font-semibold">Delta: {value?.delta ?? 'n/a'}</div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 space-y-2">
                    {(compareSummary.case_diffs || []).length === 0 ? (
                      <div className="rounded-lg border border-dashed border-slate-300 px-3 py-4 text-xs text-slate-500">No case-level behavior changes detected between these runs.</div>
                    ) : (
                      (compareSummary.case_diffs || []).map((item) => (
                        <div key={item.case_key} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                          <div className="font-medium text-slate-900">{item.case_key}</div>
                          <div className="mt-1">Pass: {String(item.left_passed)} -> {String(item.right_passed)}</div>
                          <div>Intent: {item.left_intent || 'n/a'} -> {item.right_intent || 'n/a'}</div>
                          <div>Handoff: {String(item.left_should_handoff)} -> {String(item.right_should_handoff)}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ) : null}

              {selectedEvalRun?.summary_json?.summary ? (
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
                  <div className="font-semibold text-slate-900">Summary</div>
                  <pre className="mt-2 whitespace-pre-wrap text-xs text-slate-700">{JSON.stringify(selectedEvalRun.summary_json.summary, null, 2)}</pre>
                </div>
              ) : null}

              <div className="space-y-3">
                {Array.isArray(selectedEvalRun.results) && selectedEvalRun.results.length > 0 ? selectedEvalRun.results.map((result) => (
                  <div key={result.id} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm font-semibold text-slate-900">{result.case_key}</div>
                      <div className="text-xs text-slate-500">{result.source_type}</div>
                    </div>
                    {Array.isArray(result.transcript_json) && result.transcript_json.length > 0 ? (
                      <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                        <div className="font-medium text-slate-900">Transcript</div>
                        <div className="mt-2 whitespace-pre-wrap">{result.transcript_json.join('\n')}</div>
                      </div>
                    ) : null}
                    <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                      <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                        <div className="font-medium text-slate-900">Output</div>
                        <pre className="mt-2 whitespace-pre-wrap">{JSON.stringify(result.output_json || {}, null, 2)}</pre>
                      </div>
                      <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                        <div className="font-medium text-slate-900">Score</div>
                        <pre className="mt-2 whitespace-pre-wrap">{JSON.stringify(result.score_json || {}, null, 2)}</pre>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="rounded-xl border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-500">
                    No result rows stored for this eval run.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
