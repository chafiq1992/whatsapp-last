import React, { useEffect, useMemo, useState } from 'react';
import api from './api';

function normalizeTagOptions(raw) {
  const arr = Array.isArray(raw) ? raw : [];
  const cleaned = [];
  for (const item of arr) {
    if (typeof item === 'string') {
      const label = item.trim();
      if (label) cleaned.push({ label, icon: '' });
      continue;
    }
    if (item && typeof item === 'object') {
      const label = String(item.label || '').trim();
      if (!label) continue;
      cleaned.push({ label, icon: String(item.icon || '').trim() });
    }
  }
  return cleaned;
}

export default function UsersTagsAdminPanel() {
  const [me, setMe] = useState({ username: '', is_admin: false });

  // Agents (users)
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [agentsError, setAgentsError] = useState('');
  const [agents, setAgents] = useState([]);

  const [createDraft, setCreateDraft] = useState({ username: '', name: '', password: '', is_admin: false });
  const [createSaving, setCreateSaving] = useState(false);

  const [editUsername, setEditUsername] = useState('');
  const [editDraft, setEditDraft] = useState({ name: '', is_admin: false, password: '' });
  const [editSaving, setEditSaving] = useState(false);

  // Tags
  const [tagsLoading, setTagsLoading] = useState(false);
  const [tagsError, setTagsError] = useState('');
  const [tagOptions, setTagOptions] = useState([]);
  const [tagsSaving, setTagsSaving] = useState(false);

  const canManageAgents = useMemo(() => !!me?.is_admin, [me?.is_admin]);

  const loadMe = async () => {
    try {
      const res = await api.get('/auth/me');
      setMe({ username: String(res?.data?.username || ''), is_admin: !!res?.data?.is_admin });
    } catch {
      setMe({ username: '', is_admin: false });
    }
  };

  const loadAgents = async () => {
    setAgentsError('');
    setAgentsLoading(true);
    try {
      const res = await api.get('/admin/agents');
      setAgents(Array.isArray(res.data) ? res.data : []);
    } catch (e) {
      setAgentsError('Failed to load users.');
      setAgents([]);
    } finally {
      setAgentsLoading(false);
    }
  };

  const loadTags = async () => {
    setTagsError('');
    setTagsLoading(true);
    try {
      const res = await api.get('/admin/tag-options');
      setTagOptions(normalizeTagOptions(res.data));
    } catch (e) {
      // Back-compat fallback
      try {
        const res2 = await api.get('/tag-options');
        setTagOptions(normalizeTagOptions(res2.data));
      } catch {
        setTagsError('Failed to load tags.');
        setTagOptions([]);
      }
    } finally {
      setTagsLoading(false);
    }
  };

  useEffect(() => {
    loadMe();
    loadAgents();
    loadTags();
  }, []);

  const beginEdit = (agent) => {
    const u = String(agent?.username || '').trim();
    if (!u) return;
    setEditUsername(u);
    setEditDraft({
      name: String(agent?.name || '').trim(),
      is_admin: !!agent?.is_admin,
      password: '',
    });
  };

  const cancelEdit = () => {
    setEditUsername('');
    setEditDraft({ name: '', is_admin: false, password: '' });
  };

  const saveEdit = async () => {
    const u = String(editUsername || '').trim();
    if (!u) return;
    setEditSaving(true);
    setAgentsError('');
    try {
      const payload = {
        name: String(editDraft.name || '').trim(),
        is_admin: !!editDraft.is_admin,
        ...(String(editDraft.password || '').trim() ? { password: String(editDraft.password) } : {}),
      };
      await api.put(`/admin/agents/${encodeURIComponent(u)}`, payload);
      await loadAgents();
      cancelEdit();
    } catch {
      setAgentsError('Failed to update user.');
    } finally {
      setEditSaving(false);
    }
  };

  const createAgent = async () => {
    if (!canManageAgents) return;
    const username = String(createDraft.username || '').trim();
    const password = String(createDraft.password || '');
    if (!username || !password) return;
    setCreateSaving(true);
    setAgentsError('');
    try {
      await api.post('/admin/agents', {
        username,
        name: String(createDraft.name || '').trim(),
        password,
        is_admin: !!createDraft.is_admin,
      });
      setCreateDraft({ username: '', name: '', password: '', is_admin: false });
      await loadAgents();
    } catch {
      setAgentsError('Failed to create user (username may already exist).');
    } finally {
      setCreateSaving(false);
    }
  };

  const deleteAgent = async (username) => {
    const u = String(username || '').trim();
    if (!u) return;
    if (u === String(me?.username || '')) return;
    if (!window.confirm(`Delete user "${u}"? This will immediately revoke their sessions.`)) return;
    setAgentsError('');
    try {
      await api.delete(`/admin/agents/${encodeURIComponent(u)}`);
      await loadAgents();
    } catch {
      setAgentsError('Failed to delete user.');
    }
  };

  const updateTag = (idx, field, value) => {
    setTagOptions((prev) => prev.map((t, i) => (i === idx ? { ...t, [field]: value } : t)));
  };

  const addTag = () => setTagOptions((prev) => [...(prev || []), { label: '', icon: '' }]);
  const removeTag = (idx) => setTagOptions((prev) => prev.filter((_, i) => i !== idx));

  const saveTags = async () => {
    setTagsSaving(true);
    setTagsError('');
    try {
      const cleaned = normalizeTagOptions(tagOptions).map((t) => ({ label: t.label, icon: t.icon }));
      await api.post('/admin/tag-options', { options: cleaned });
      await loadTags();
    } catch {
      setTagsError('Failed to save tags.');
    } finally {
      setTagsSaving(false);
    }
  };

  return (
    <div className="grid grid-cols-12 gap-4">
      {/* Users */}
      <div className="col-span-12 lg:col-span-7 space-y-3">
        <div className="border rounded bg-white">
          <div className="px-3 py-2 border-b text-sm font-medium">Users</div>
          <div className="p-3 space-y-3">
            {agentsError && <div className="p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{agentsError}</div>}
            {agentsLoading ? (
              <div className="text-sm text-slate-500">Loading users…</div>
            ) : (
              <div className="overflow-auto border rounded">
                <table className="min-w-full text-sm">
                  <thead className="bg-slate-50 text-slate-600">
                    <tr>
                      <th className="text-left px-3 py-2 font-medium">Username</th>
                      <th className="text-left px-3 py-2 font-medium">Name</th>
                      <th className="text-left px-3 py-2 font-medium">Role</th>
                      <th className="text-right px-3 py-2 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(agents || []).map((a) => {
                      const u = String(a?.username || '');
                      const isMe = u && u === String(me?.username || '');
                      const isEditing = u && u === editUsername;
                      return (
                        <React.Fragment key={u || Math.random()}>
                          <tr className="border-t">
                            <td className="px-3 py-2 font-mono text-xs">{u}</td>
                            <td className="px-3 py-2">{String(a?.name || '')}</td>
                            <td className="px-3 py-2">
                              {a?.is_admin ? <span className="text-emerald-700 font-medium">Admin</span> : <span className="text-slate-600">Agent</span>}
                              {isMe ? <span className="ml-2 text-[11px] text-slate-500">(you)</span> : null}
                            </td>
                            <td className="px-3 py-2 text-right">
                              <div className="inline-flex items-center gap-2">
                                <button
                                  type="button"
                                  className="px-2 py-1 rounded border bg-white hover:bg-slate-50 text-sm"
                                  onClick={() => beginEdit(a)}
                                  disabled={!canManageAgents}
                                >
                                  Edit
                                </button>
                                <button
                                  type="button"
                                  className="px-2 py-1 rounded bg-rose-600 text-white disabled:opacity-50 text-sm"
                                  onClick={() => deleteAgent(u)}
                                  disabled={!canManageAgents || isMe}
                                  title={isMe ? 'You cannot delete your own account' : 'Delete user'}
                                >
                                  Delete
                                </button>
                              </div>
                            </td>
                          </tr>

                          {isEditing && (
                            <tr className="border-t bg-slate-50">
                              <td className="px-3 py-3" colSpan={4}>
                                <div className="grid grid-cols-12 gap-2 items-end">
                                  <div className="col-span-12 md:col-span-5">
                                    <div className="text-xs text-slate-500 mb-1">Name</div>
                                    <input
                                      className="w-full border rounded px-2 py-1"
                                      value={editDraft.name}
                                      onChange={(e) => setEditDraft((d) => ({ ...d, name: e.target.value }))}
                                    />
                                  </div>
                                  <div className="col-span-12 md:col-span-3">
                                    <label className="text-sm flex items-center gap-2">
                                      <input
                                        type="checkbox"
                                        checked={!!editDraft.is_admin}
                                        onChange={(e) => setEditDraft((d) => ({ ...d, is_admin: !!e.target.checked }))}
                                      />
                                      Admin
                                    </label>
                                  </div>
                                  <div className="col-span-12 md:col-span-4">
                                    <div className="text-xs text-slate-500 mb-1">Reset password (optional)</div>
                                    <input
                                      type="password"
                                      className="w-full border rounded px-2 py-1 font-mono text-xs"
                                      value={editDraft.password}
                                      onChange={(e) => setEditDraft((d) => ({ ...d, password: e.target.value }))}
                                      placeholder="Leave blank to keep"
                                    />
                                  </div>
                                  <div className="col-span-12 flex items-center justify-end gap-2">
                                    <button type="button" className="px-3 py-1.5 rounded border bg-white hover:bg-slate-50" onClick={cancelEdit} disabled={editSaving}>
                                      Cancel
                                    </button>
                                    <button
                                      type="button"
                                      className="px-3 py-1.5 rounded bg-gray-900 text-white disabled:opacity-50"
                                      onClick={saveEdit}
                                      disabled={editSaving}
                                    >
                                      {editSaving ? 'Saving…' : 'Save'}
                                    </button>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                    {(agents || []).length === 0 && (
                      <tr>
                        <td className="px-3 py-3 text-slate-500" colSpan={4}>No users found.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="border rounded bg-white">
          <div className="px-3 py-2 border-b text-sm font-medium">Add user</div>
          <div className="p-3 grid grid-cols-12 gap-2 items-end">
            <div className="col-span-12 md:col-span-4">
              <div className="text-xs text-slate-500 mb-1">Username</div>
              <input className="w-full border rounded px-2 py-1 font-mono text-sm" value={createDraft.username} onChange={(e) => setCreateDraft((d) => ({ ...d, username: e.target.value }))} placeholder="e.g. sara" />
            </div>
            <div className="col-span-12 md:col-span-4">
              <div className="text-xs text-slate-500 mb-1">Name</div>
              <input className="w-full border rounded px-2 py-1 text-sm" value={createDraft.name} onChange={(e) => setCreateDraft((d) => ({ ...d, name: e.target.value }))} placeholder="Display name" />
            </div>
            <div className="col-span-12 md:col-span-4">
              <div className="text-xs text-slate-500 mb-1">Password</div>
              <input className="w-full border rounded px-2 py-1 font-mono text-xs" type="password" value={createDraft.password} onChange={(e) => setCreateDraft((d) => ({ ...d, password: e.target.value }))} placeholder="Temporary password" />
            </div>
            <div className="col-span-12 md:col-span-6">
              <label className="text-sm flex items-center gap-2">
                <input type="checkbox" checked={!!createDraft.is_admin} onChange={(e) => setCreateDraft((d) => ({ ...d, is_admin: !!e.target.checked }))} />
                Make admin
              </label>
            </div>
            <div className="col-span-12 md:col-span-6 flex justify-end">
              <button
                type="button"
                className="px-3 py-2 rounded bg-blue-600 text-white disabled:opacity-50"
                disabled={!canManageAgents || createSaving || !String(createDraft.username || '').trim() || !String(createDraft.password || '').trim()}
                onClick={createAgent}
              >
                {createSaving ? 'Saving…' : 'Create user'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Tags */}
      <div className="col-span-12 lg:col-span-5 space-y-3">
        <div className="border rounded bg-white">
          <div className="px-3 py-2 border-b text-sm font-medium">Tags</div>
          <div className="p-3 space-y-3">
            {tagsError && <div className="p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{tagsError}</div>}
            {tagsLoading ? (
              <div className="text-sm text-slate-500">Loading tags…</div>
            ) : (
              <div className="space-y-2">
                {(tagOptions || []).map((t, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <input
                      className="w-16 border rounded px-2 py-1 text-sm"
                      placeholder="icon"
                      value={t.icon || ''}
                      onChange={(e) => updateTag(idx, 'icon', e.target.value)}
                      title="Optional icon (emoji)"
                    />
                    <input
                      className="flex-1 border rounded px-2 py-1 text-sm"
                      placeholder="Tag label (e.g. Done)"
                      value={t.label || ''}
                      onChange={(e) => updateTag(idx, 'label', e.target.value)}
                    />
                    <button type="button" className="px-2 py-1 rounded bg-rose-600 text-white" onClick={() => removeTag(idx)} title="Remove tag">
                      Remove
                    </button>
                  </div>
                ))}
                {(tagOptions || []).length === 0 && <div className="text-sm text-slate-500">No tags yet.</div>}
                <div className="flex items-center justify-between gap-2 pt-2 border-t">
                  <button type="button" className="px-3 py-2 rounded border bg-white hover:bg-slate-50" onClick={addTag}>
                    + Add tag
                  </button>
                  <button
                    type="button"
                    className="px-3 py-2 rounded bg-gray-900 text-white disabled:opacity-50"
                    disabled={!canManageAgents || tagsSaving}
                    onClick={saveTags}
                    title={!canManageAgents ? 'Admin required' : 'Save tag options'}
                  >
                    {tagsSaving ? 'Saving…' : 'Save tags'}
                  </button>
                </div>
                <div className="text-[11px] text-slate-500">
                  These options appear in the chat list filters and when editing conversation tags.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


