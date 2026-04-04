import React from 'react';
import { Handle, Position } from '@xyflow/react';
import {
  ShoppingCart, MessageSquare, ScanLine, Activity, Plus,
  SplitSquareHorizontal, Timer, Ban, Zap, MousePointerClick,
  AlertTriangle, CheckCircle2, XCircle,
} from 'lucide-react';

/* ── colour map ─────────────────────────────────────────── */
const TRIGGER_COLOURS = {
  shopify:     { bg: 'bg-emerald-50',  border: 'border-emerald-300', accent: 'text-emerald-600', ring: 'ring-emerald-200' },
  whatsapp:    { bg: 'bg-green-50',    border: 'border-green-300',   accent: 'text-green-600',   ring: 'ring-green-200'   },
  delivery:    { bg: 'bg-sky-50',      border: 'border-sky-300',     accent: 'text-sky-600',     ring: 'ring-sky-200'     },
  retargeting: { bg: 'bg-purple-50',   border: 'border-purple-300',  accent: 'text-purple-600',  ring: 'ring-purple-200'  },
};
const TRIGGER_ICONS = {
  shopify:     <ShoppingCart className="w-5 h-5" />,
  whatsapp:    <MessageSquare className="w-5 h-5" />,
  delivery:    <ScanLine className="w-5 h-5" />,
  retargeting: <Activity className="w-5 h-5" />,
};

/* ── Error badge — shown on any node with validation errors ── */
function ErrorBadge({ errors }) {
  if (!errors || !errors.length) return null;
  return (
    <div
      className="absolute -top-3 -right-3 z-20 flex items-center gap-1 bg-rose-600 text-white text-[9px] font-bold px-2 py-0.5 rounded-full shadow-lg cursor-help border-2 border-white"
      title={errors.join('\n')}
    >
      <AlertTriangle className="w-2.5 h-2.5" />
      <span>{errors.length}</span>
    </div>
  );
}

/* ── Metrics badge ──────────────────────────────────────── */
function MetricsBadge({ metrics }) {
  if (!metrics) return null;
  const runs = metrics.runs || 0;
  const triggers = metrics.triggers || 0;
  const count = runs || triggers;
  if (!count) return null;
  return (
    <div className="absolute -top-2.5 -right-2.5 flex items-center gap-1 bg-slate-800 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full shadow-lg z-10 border border-slate-700">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
      {count.toLocaleString()}
    </div>
  );
}

/* ── Last run status badge ──────────────────────────────── */
function LastRunBadge({ status }) {
  if (!status) return null;
  const isSuccess = status.status === 'success';
  const isError = status.status === 'error';
  if (!isSuccess && !isError) return null;
  const timeAgo = status.timestamp ? (() => {
    try {
      const diff = Date.now() - new Date(status.timestamp).getTime();
      const mins = Math.round(diff / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return mins + 'm ago';
      const hrs = Math.round(mins / 60);
      if (hrs < 24) return hrs + 'h ago';
      return Math.round(hrs / 24) + 'd ago';
    } catch { return ''; }
  })() : '';
  return (
    <div
      className={`absolute -bottom-2.5 left-1/2 -translate-x-1/2 z-20 flex items-center gap-1 text-[9px] font-bold px-2 py-0.5 rounded-full shadow-lg border-2 border-white cursor-help transition-all ${
        isSuccess ? 'bg-emerald-500 text-white' : 'bg-rose-500 text-white'
      }`}
      title={isError ? `Error: ${status.message || 'Unknown error'}\n${timeAgo}` : `Success ${timeAgo}`}
    >
      {isSuccess ? <CheckCircle2 className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />}
      <span>{isSuccess ? (timeAgo || '✓') : '✗'}</span>
    </div>
  );
}

/* ── Handle with hover glow for discoverability ──────── */
function ConnectableHandle({ type, position, id, className, style, ...rest }) {
  return (
    <Handle
      type={type}
      position={position}
      id={id}
      className={`!w-3.5 !h-3.5 !border-2 !border-white !shadow-md hover:!scale-150 hover:!shadow-lg transition-all ${className || ''}`}
      style={style}
      {...rest}
    />
  );
}

/* ── Start trigger placeholder ──────────────────────────── */
export function StartTriggerNode({ data }) {
  const isConfigured = data?.configured;
  const errors = data?.errors;
  return (
    <div
      className="relative cursor-pointer group"
      onClick={() => data?.onSelect?.()}
    >
      <ErrorBadge errors={errors} />
      <MetricsBadge metrics={data?.metrics} />
      <LastRunBadge status={data?.lastRunStatus} />
      {isConfigured ? (
        <div className={`rounded-2xl shadow-lg border-2 ${TRIGGER_COLOURS[data.source]?.border || 'border-emerald-300'} ${TRIGGER_COLOURS[data.source]?.bg || 'bg-emerald-50'} p-5 min-w-[280px] transition-all hover:shadow-xl hover:scale-[1.02]`}>
          <div className="flex items-center gap-3 mb-3">
            <div className={`p-2.5 rounded-xl bg-white shadow-sm ${TRIGGER_COLOURS[data.source]?.accent || 'text-emerald-600'}`}>
              {TRIGGER_ICONS[data.source] || <Zap className="w-5 h-5" />}
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-0.5">When</div>
              <div className="text-sm font-semibold text-slate-800 truncate">{data.label || 'Trigger'}</div>
            </div>
          </div>
          {data.description && (
            <div className="text-xs text-slate-500 bg-white/60 rounded-lg px-3 py-2 mb-2">{data.description}</div>
          )}
          <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Click to edit trigger
          </div>
        </div>
      ) : (
        <div className="rounded-2xl border-2 border-dashed border-slate-300 bg-white p-8 min-w-[280px] flex flex-col items-center gap-3 hover:border-blue-400 hover:bg-blue-50/30 transition-all group">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white shadow-lg group-hover:scale-110 transition-transform">
            <Zap className="w-7 h-7" />
          </div>
          <div className="text-sm font-semibold text-slate-700">Select a trigger</div>
          <div className="text-xs text-slate-400 text-center">Choose an event that starts<br/>your workflow</div>
        </div>
      )}
      <ConnectableHandle type="source" position={Position.Bottom} className="!bg-blue-500" />
    </div>
  );
}

/* ── Condition node ──────────────────────────────────────── */
export function ConditionFlowNode({ data }) {
  const errors = data?.errors;
  return (
    <div
      className="relative cursor-pointer group"
      onClick={() => data?.onSelect?.()}
    >
      <ErrorBadge errors={errors} />
      <MetricsBadge metrics={data?.metrics} />
      <LastRunBadge status={data?.lastRunStatus} />
      <ConnectableHandle type="target" position={Position.Top} className="!bg-amber-500" />
      <div className="rounded-2xl shadow-lg border-2 border-amber-300 bg-amber-50 p-5 min-w-[280px] transition-all hover:shadow-xl hover:scale-[1.02]">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2.5 rounded-xl bg-white shadow-sm text-amber-600">
            <SplitSquareHorizontal className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-0.5">If</div>
            <div className="text-sm font-semibold text-slate-800">Condition</div>
          </div>
        </div>
        {data.expression ? (
          <div className="text-xs text-slate-600 bg-white/60 rounded-lg px-3 py-2 mb-2 font-medium">
            Check if: <span className="text-amber-700">{data.expression}</span>
          </div>
        ) : (
          <div className="text-xs text-slate-400 bg-white/60 rounded-lg px-3 py-2 mb-2 italic">
            Click to set condition…
          </div>
        )}
        <div className="flex gap-4 text-[10px]">
          <span className="text-emerald-600 font-semibold">✓ {data.trueLabel || 'Then'}</span>
          <span className="text-rose-500 font-semibold">✗ {data.falseLabel || 'Otherwise'}</span>
        </div>
      </div>
      {/* True branch (left-bottom) & False branch (right-bottom) */}
      <ConnectableHandle type="source" position={Position.Bottom} id="true" className="!bg-emerald-500" style={{ left: '30%' }} />
      <ConnectableHandle type="source" position={Position.Bottom} id="false" className="!bg-rose-500" style={{ left: '70%' }} />
    </div>
  );
}

/* ── Action node ─────────────────────────────────────────── */
export function ActionFlowNode({ data }) {
  const actionLabel = data?.actionLabel || data?.label || 'Action';
  const isExit = data?.actionType === 'exit';
  const buttonChildIds = data?.buttonChildIds || [];
  const buttonDefs = data?.buttonDefs || []; // [{id, text}]
  const errors = data?.errors;

  return (
    <div
      className="relative cursor-pointer group"
      onClick={() => data?.onSelect?.()}
    >
      <ErrorBadge errors={errors} />
      <MetricsBadge metrics={data?.metrics} />
      <LastRunBadge status={data?.lastRunStatus} />
      <ConnectableHandle type="target" position={Position.Top} className="!bg-blue-500" />
      <div className={`rounded-2xl shadow-lg border-2 p-5 min-w-[280px] transition-all hover:shadow-xl hover:scale-[1.02] ${isExit ? 'border-rose-300 bg-rose-50' : 'border-blue-300 bg-blue-50'}`}>
        <div className="flex items-center gap-3 mb-3">
          <div className={`p-2.5 rounded-xl bg-white shadow-sm ${isExit ? 'text-rose-500' : 'text-blue-600'}`}>
            {isExit ? <Ban className="w-5 h-5" /> : <MessageSquare className="w-5 h-5" />}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-0.5">Then</div>
            <div className="text-sm font-semibold text-slate-800 truncate">{actionLabel}</div>
          </div>
        </div>
        {data.description && (
          <div className="text-xs text-slate-500 bg-white/60 rounded-lg px-3 py-2 mb-2">{data.description}</div>
        )}
        {buttonDefs.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {buttonDefs.map((btn, i) => (
              <span key={i} className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-700 border border-indigo-200 font-medium">
                {btn.text || btn.id}
              </span>
            ))}
          </div>
        )}
        {!buttonDefs.length && (
          <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-medium">
            Click to configure
          </div>
        )}
      </div>
      {/* Default bottom handle — only shown when no button children */}
      {buttonChildIds.length === 0 && (
        <ConnectableHandle type="source" position={Position.Bottom} className="!bg-blue-500" />
      )}
      {/* Per-button source handles */}
      {buttonChildIds.length > 0 && buttonDefs.map((btn, i) => {
        const total = buttonDefs.length;
        const pct = total === 1 ? 50 : 20 + (i / (total - 1)) * 60;
        return (
          <ConnectableHandle
            key={`btn_${i}`}
            type="source"
            position={Position.Bottom}
            id={`btn_${i}`}
            className="!bg-indigo-500"
            style={{ left: `${pct}%` }}
          />
        );
      })}
    </div>
  );
}

/* ── Add-step placeholder (the + button between nodes) ─── */
export function AddStepNode({ data }) {
  return (
    <div className="relative">
      <Handle type="target" position={Position.Top} className="!w-0 !h-0 !bg-transparent !border-none" />
      <div
        className="w-10 h-10 rounded-full bg-white border-2 border-dashed border-slate-300 flex items-center justify-center cursor-pointer hover:border-blue-400 hover:bg-blue-50 transition-all hover:scale-110 shadow-sm group"
        onClick={() => data?.onAdd?.()}
        title="Add next step"
      >
        <Plus className="w-5 h-5 text-slate-400 group-hover:text-blue-500 transition-colors" />
      </div>
    </div>
  );
}

/* ── Delay node ──────────────────────────────────────────── */
export function DelayFlowNode({ data }) {
  const errors = data?.errors;
  return (
    <div
      className="relative cursor-pointer group"
      onClick={() => data?.onSelect?.()}
    >
      <ErrorBadge errors={errors} />
      <MetricsBadge metrics={data?.metrics} />
      <LastRunBadge status={data?.lastRunStatus} />
      <ConnectableHandle type="target" position={Position.Top} className="!bg-violet-500" />
      <div className="rounded-2xl shadow-lg border-2 border-violet-300 bg-violet-50 p-5 min-w-[280px] transition-all hover:shadow-xl hover:scale-[1.02]">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2.5 rounded-xl bg-white shadow-sm text-violet-600">
            <Timer className="w-5 h-5" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-0.5">Wait</div>
            <div className="text-sm font-semibold text-slate-800">
              {data.minutes ? `${data.minutes} minute${data.minutes > 1 ? 's' : ''}` : 'Set delay…'}
            </div>
          </div>
        </div>
      </div>
      <ConnectableHandle type="source" position={Position.Bottom} className="!bg-violet-500" />
    </div>
  );
}

/* ── Button Reply node ───────────────────────────────────── */
export function ButtonReplyNode({ data }) {
  const btnText = data?.buttonText || 'Button';
  const multiActions = Array.isArray(data?.replyActions) ? data.replyActions : [];
  const hasAction = multiActions.length > 0 || !!data?.replyActionType;
  const actionCount = multiActions.length || (data?.replyActionType ? 1 : 0);
  const errors = data?.errors;
  return (
    <div
      className="relative cursor-pointer group"
      onClick={() => data?.onSelect?.()}
    >
      <ErrorBadge errors={errors} />
      <MetricsBadge metrics={data?.metrics} />
      <LastRunBadge status={data?.lastRunStatus} />
      <ConnectableHandle type="target" position={Position.Top} className="!bg-indigo-400" />
      <div className="rounded-xl shadow-md border-2 border-indigo-300 bg-indigo-50 px-4 py-3 min-w-[200px] transition-all hover:shadow-lg hover:scale-[1.02]">
        <div className="flex items-center gap-2 mb-1.5">
          <div className="p-1.5 rounded-lg bg-white shadow-sm text-indigo-600">
            <MousePointerClick className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[9px] font-bold uppercase tracking-widest text-indigo-400 mb-0">Button Reply</div>
            <div className="text-xs font-semibold text-slate-800 truncate">"{btnText}"</div>
          </div>
        </div>
        <div className={`text-[10px] px-2 py-1 rounded-lg font-medium ${hasAction ? 'bg-indigo-100 text-indigo-700' : 'bg-white/60 text-slate-400 italic'}`}>
          {hasAction
            ? actionCount > 1 ? `⚡ ${actionCount} actions` : `→ ${multiActions[0]?.replyActionLabel || data.replyActionLabel || data.replyActionType || 'Action'}`
            : 'Click to set reply action'}
        </div>
      </div>
      <ConnectableHandle type="source" position={Position.Bottom} className="!bg-indigo-400" />
    </div>
  );
}

export const flowNodeTypes = {
  startTrigger:  StartTriggerNode,
  conditionFlow: ConditionFlowNode,
  actionFlow:    ActionFlowNode,
  addStep:       AddStepNode,
  delayFlow:     DelayFlowNode,
  buttonReply:   ButtonReplyNode,
};
