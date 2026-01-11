import React, { useEffect, useMemo, useRef, useState } from 'react';
import { HiChatBubbleLeftRight, HiInboxArrowDown, HiArchiveBox, HiCog6Tooth, HiUserCircle, HiPlus, HiArrowLeftOnRectangle } from 'react-icons/hi2';
import api from './api';

export default function MiniSidebar({
	showArchive = false,
	onSetShowArchive,
	onToggleInternal,
	onSelectInternalAgent,
	onOpenSettings,
  currentAgent = '',
  isAdmin = false,
  onStartNewChat,
  workspace = 'irranova',
  onSwitchWorkspace,
}) {
	const [showDropdown, setShowDropdown] = useState(false);
  const [showWsDropdown, setShowWsDropdown] = useState(false);
	const [agents, setAgents] = useState([]);
  const [onlineAgents, setOnlineAgents] = useState([]);
	const buttonRef = useRef(null);
	const dropdownRef = useRef(null);
  const wsButtonRef = useRef(null);
  const wsDropdownRef = useRef(null);
  const [showNewChat, setShowNewChat] = useState(false);
  const [newChatValue, setNewChatValue] = useState('');
  const [workspacesConfig, setWorkspacesConfig] = useState({ workspaces: [], defaultWorkspace: '' });

	useEffect(() => {
		(async () => {
			try {
				const res = await api.get('/agents');
				setAgents(res.data || []);
			} catch {}
		})();
	}, []);

  // Load runtime config for workspace catalog (labels + available workspaces)
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await api.get('/app-config');
        const data = res?.data || {};
        const list = Array.isArray(data.workspaces) ? data.workspaces : [];
        const norm = list
          .map((w) => ({
            id: String(w?.id || '').trim().toLowerCase(),
            label: String(w?.label || '').trim(),
            short: String(w?.short || '').trim(),
          }))
          .filter((w) => w.id);
        if (!alive) return;
        setWorkspacesConfig({
          workspaces: norm,
          defaultWorkspace: String(data.defaultWorkspace || '').trim().toLowerCase(),
        });
      } catch {
        if (!alive) return;
        setWorkspacesConfig({ workspaces: [], defaultWorkspace: '' });
      }
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;

    const normalize = (data) => {
      if (!data) return [];
      const arr = Array.isArray(data) ? data : (Array.isArray(data?.online_agents) ? data.online_agents : []);
      return arr
        .map((x) => (typeof x === 'string' ? x : (x?.username || '')))
        .map((x) => String(x || '').trim())
        .filter(Boolean);
    };

    const load = async () => {
      try {
        const res = await api.get('/agents/online');
        if (!alive) return;
        setOnlineAgents(normalize(res?.data));
      } catch {
        if (!alive) return;
        setOnlineAgents([]);
      }
    };

    load();
    const t = setInterval(load, 10000);
    return () => {
      alive = false;
      try { clearInterval(t); } catch {}
    };
  }, [workspace]);

	useEffect(() => {
		const handler = (e) => {
			if (!showDropdown) return;
			const t = e.target;
			if (!dropdownRef.current || !buttonRef.current) return;
			if (!dropdownRef.current.contains(t) && !buttonRef.current.contains(t)) {
				setShowDropdown(false);
			}
		};
		document.addEventListener('mousedown', handler);
		return () => document.removeEventListener('mousedown', handler);
	}, [showDropdown]);

  useEffect(() => {
    const handler = (e) => {
      if (!showWsDropdown) return;
      const t = e.target;
      if (!wsDropdownRef.current || !wsButtonRef.current) return;
      if (!wsDropdownRef.current.contains(t) && !wsButtonRef.current.contains(t)) {
        setShowWsDropdown(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showWsDropdown]);

	// Resolve display name for current agent (prefer friendly name if available)
	const displayName = (() => {
		try {
			const a = agents.find(x => String(x.username || '').toLowerCase() === String(currentAgent || '').toLowerCase());
			return (a?.name || currentAgent || '').toString();
		} catch { return currentAgent || ''; }
	})();

  const onlineSet = useMemo(() => {
    try {
      return new Set((onlineAgents || []).map((x) => String(x || '').toLowerCase()));
    } catch {
      return new Set();
    }
  }, [onlineAgents]);

  const onlineList = useMemo(() => {
    try {
      return (agents || []).filter((a) => onlineSet.has(String(a?.username || '').toLowerCase()));
    } catch {
      return [];
    }
  }, [agents, onlineSet]);

  const initialsOf = (name) => {
    try {
      const s = String(name || '').trim();
      if (!s) return '?';
      const parts = s.split(/\s+/).filter(Boolean);
      if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    } catch {
      return '?';
    }
  };

  const workspaces = useMemo(() => {
    const fromCfg = (workspacesConfig?.workspaces || []).filter(Boolean);
    if (fromCfg.length) return fromCfg;
    // fallback to legacy two-workspace setup
    return [
      { id: 'irranova', label: 'IRRANOVA', short: 'NOVA' },
      { id: 'irrakids', label: 'IRRAKIDS', short: 'KIDS' },
    ];
  }, [workspacesConfig]);

  const currentWorkspaceObj = useMemo(() => {
    const ws = String(workspace || '').trim().toLowerCase();
    return workspaces.find((w) => w.id === ws) || null;
  }, [workspaces, workspace]);

  const workspaceButtonText = (() => {
    const s = String(currentWorkspaceObj?.short || currentWorkspaceObj?.label || workspace || '').trim();
    if (!s) return 'WS';
    return s.length > 5 ? s.slice(0, 5).toUpperCase() : s.toUpperCase();
  })();

	return (
		<div className="w-16 bg-gray-900 border-r border-gray-800 h-full flex flex-col items-center justify-between py-3 relative">
			{/* Upper section */}
			<div className="flex flex-col items-center gap-3">
        <div className="relative">
          <button
            ref={wsButtonRef}
            type="button"
            title={`Workspace: ${String(currentWorkspaceObj?.label || workspace || '').toUpperCase()}`}
            onClick={() => setShowWsDropdown(v => !v)}
            className={`w-12 h-10 rounded-xl flex items-center justify-center text-xs font-extrabold tracking-widest border transition-colors ${
              (() => {
                const idx = workspaces.findIndex((w) => w.id === String(workspace || '').toLowerCase());
                if (idx === 1) return 'bg-[#004AAD] text-white border-[#004AAD]';
                if (idx === 0) return 'bg-green-700 text-white border-green-700';
                return 'bg-gray-800 text-white border-gray-700';
              })()
            }`}
          >
            {workspaceButtonText}
          </button>
          {showWsDropdown && (
            <div
              ref={wsDropdownRef}
              className="absolute left-16 top-0 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 w-56 max-h-72 overflow-auto"
            >
              <div className="p-2 text-sm text-gray-300 border-b border-gray-800 sticky top-0 bg-gray-900">
                Workspaces
              </div>
              <div className="p-1">
                {(workspaces || []).map((w) => (
                  <button
                    key={`ws:${w.id}`}
                    type="button"
                    onClick={() => {
                      try {
                        if (typeof onSwitchWorkspace === 'function') onSwitchWorkspace(w.id);
                        setShowWsDropdown(false);
                      } catch {}
                    }}
                    className={`w-full flex items-center justify-between gap-2 px-2 py-2 hover:bg-gray-800 rounded text-left ${
                      String(w.id) === String(workspace || '').toLowerCase() ? 'bg-gray-800' : ''
                    }`}
                    title={String(w.label || w.id)}
                  >
                    <span className="truncate text-gray-200">{String(w.label || w.id)}</span>
                    <span className="text-xs text-gray-400 font-mono">{String(w.short || '').toUpperCase()}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
				<button
					type="button"
					title="New chat"
					onClick={() => setShowNewChat(v => !v)}
					className="w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-green-700 text-white hover:bg-green-600"
				>
					<HiPlus />
				</button>
				{showNewChat && (
					<div className="absolute left-16 top-3 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 w-64 p-3">
						<div className="text-sm text-gray-300 mb-2">Start new chat</div>
						<div className="flex gap-2">
							<input
								type="tel"
								placeholder="WhatsApp number"
								value={newChatValue}
								onChange={(e) => setNewChatValue(e.target.value)}
								className="flex-1 px-2 py-1 bg-gray-800 text-white rounded border border-gray-700"
							/>
							<button
								type="button"
								className="px-3 py-1 rounded bg-blue-600 text-white disabled:opacity-50"
								onClick={() => {
									try {
										const cleaned = String(newChatValue || '').replace(/[^\d+]/g, '');
										const digits = cleaned.replace(/\D/g, '');
										if (digits.length < 8) return;
										if (typeof onStartNewChat === 'function') {
											onStartNewChat(digits, cleaned);
										}
										setShowNewChat(false);
										setNewChatValue('');
									} catch {}
								}}
								disabled={!newChatValue || newChatValue.trim().length < 4}
							>
								Start
							</button>
						</div>
					</div>
				)}
				<button
					type="button"
					title="Inbox"
					onClick={() => onSetShowArchive && onSetShowArchive(false)}
					className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl transition-colors ${!showArchive ? 'bg-[#004AAD] text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
				>
					<HiInboxArrowDown />
				</button>
				<button
					type="button"
					title="Archive"
					onClick={() => onSetShowArchive && onSetShowArchive(true)}
					className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl transition-colors ${showArchive ? 'bg-[#004AAD] text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
				>
					<HiArchiveBox />
				</button>
        <div className="relative flex flex-col items-center">
				<button
					type="button"
					title="Internal chats"
					onClick={() => {
						setShowDropdown(v => !v);
						if (onToggleInternal) onToggleInternal();
					}}
					className="w-14 h-14 rounded-xl flex items-center justify-center text-3xl bg-gray-800 text-gray-300 hover:bg-gray-700"
					ref={buttonRef}
				>
					<HiChatBubbleLeftRight />
				</button>
          {onlineList.length > 0 && (
            <div
              className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 rounded-full bg-emerald-600 text-white text-[11px] flex items-center justify-center border border-gray-900"
              title={`${onlineList.length} agent(s) online`}
            >
              {onlineList.length}
            </div>
          )}

          {/* Online agents visible under the internal chats icon */}
          {onlineList.length > 0 && (
            <div className="mt-2 flex flex-col items-center gap-2">
              {onlineList.slice(0, 4).map((a) => (
                <button
                  key={`online-pill:${a.username}`}
                  type="button"
                  onClick={() => {
                    try {
                      if (onSelectInternalAgent) onSelectInternalAgent(a.username);
                    } catch {}
                  }}
                  title={`@${a.name || a.username} • online`}
                  className="w-12 h-12 rounded-xl flex items-center justify-center bg-gray-800 border border-emerald-600 text-emerald-300 hover:bg-gray-700"
                >
                  <div className="relative w-full h-full flex items-center justify-center">
                    <span className="text-xs font-bold tracking-wide">{initialsOf(a.name || a.username)}</span>
                    <span className="absolute -bottom-1 -right-1 w-3 h-3 rounded-full bg-emerald-500 border border-gray-900" />
                  </div>
                </button>
              ))}
              {onlineList.length > 4 && (
                <div
                  className="w-12 h-8 rounded-xl flex items-center justify-center bg-gray-800 border border-emerald-700 text-emerald-300 text-xs"
                  title={`${onlineList.length - 4} more online`}
                >
                  +{onlineList.length - 4}
                </div>
              )}
            </div>
          )}
        </div>
				{showDropdown && (
					<div ref={dropdownRef} className="absolute left-16 top-16 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 w-64 max-h-72 overflow-auto">
						<div className="p-2 text-sm text-gray-300 border-b border-gray-800 sticky top-0 bg-gray-900">Internal chats</div>
						<div className="p-1">
              <div className="px-2 pt-1 pb-1 text-xs text-gray-400">All agents</div>
							{agents.map(a => (
								<button
									key={a.username}
									type="button"
									onClick={() => {
										if (onSelectInternalAgent) onSelectInternalAgent(a.username);
										setShowDropdown(false);
									}}
									className="w-full flex items-center gap-2 px-2 py-2 hover:bg-gray-800 rounded text-left"
									title={`DM @${a.name || a.username}`}
								>
									{onlineSet.has(String(a.username || '').toLowerCase()) ? (
                    <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  ) : (
                    <span className="w-2 h-2 rounded-full bg-gray-600" />
                  )}
									<HiUserCircle className={`text-2xl ${onlineSet.has(String(a.username || '').toLowerCase()) ? 'text-emerald-400' : ''}`} />
									<span className="truncate">@{a.name || a.username}</span>
								</button>
							))}
							{agents.length === 0 && (
								<div className="text-sm text-gray-400 px-2 py-2">No agents</div>
							)}
						</div>
					</div>
				)}
			</div>

			{/* Agent name (vertical, carved effect) */}
			{(displayName && displayName.trim()) && (
				<div className="flex-1 flex items-center justify-center select-none">
					<div className="flex flex-col items-center" aria-label="agent-name">
						{displayName.toUpperCase().split('').map((ch, i) => (
							<div
								key={i}
								className="text-gray-300 font-extrabold"
								style={{
									fontSize: '20px',
									letterSpacing: '0.1em',
									lineHeight: '22px',
									textShadow: '0 1px 0 rgba(255,255,255,0.14), 0 -1px 0 rgba(0,0,0,0.65), 0 2px 6px rgba(0,0,0,0.6)'
								}}
							>
								{ch}
							</div>
						))}
					</div>
				</div>
			)}

			{/* Lower section */}
			<div className="flex flex-col items-center gap-3">
        <button
          type="button"
          title="Logout"
          onClick={async () => {
            try { await api.post('/auth/logout'); } catch {}
            try { sessionStorage.removeItem('agent_access_token'); } catch {}
            try { sessionStorage.removeItem('agent_refresh_token'); } catch {}
            try { localStorage.removeItem('agent_access_token'); } catch {}
            try { localStorage.removeItem('agent_refresh_token'); } catch {}
            try { localStorage.removeItem('agent_is_admin'); } catch {}
            try { window.location.replace('/login'); } catch {}
          }}
          className="w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-gray-800 text-gray-300 hover:bg-gray-700"
        >
          <HiArrowLeftOnRectangle />
        </button>
				<button
					type="button"
					title="Settings"
					onClick={() => onOpenSettings && onOpenSettings()}
					className="w-12 h-12 rounded-xl flex items-center justify-center text-2xl bg-gray-800 text-gray-300 hover:bg-gray-700"
				>
					<HiCog6Tooth />
				</button>
			</div>
		</div>
	);
}


