import React from 'react';
import { Zap, BarChart2, MessageSquare, CheckCircle2, XCircle, Clock } from 'lucide-react';

/**
 * FlowSummaryPanel — Always-visible side panel showing flow overview
 * when no node/picker is selected.
 */
export default function FlowSummaryPanel({ nodes, edges, flowName, flowEnabled, triggerNode, validationErrors, flowStat, lastRunStatus }) {
  const realNodes = (nodes || []).filter(n => n.type !== 'addStep');
  const actionCount = realNodes.filter(n => n.type === 'actionFlow').length;
  const conditionCount = realNodes.filter(n => n.type === 'conditionFlow').length;
  const delayCount = realNodes.filter(n => n.type === 'delayFlow').length;
  const totalErrors = validationErrors ? validationErrors.size : 0;
  const nodeErrors = (nodes || []).filter(n => validationErrors?.has(n.id)).length;

  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">Flow Overview</h3>
      </div>
      <div className="p-4 space-y-4 flex-1 overflow-y-auto">
        {/* Flow name & status */}
        <div className="p-4 rounded-xl bg-gradient-to-br from-slate-50 to-blue-50 border border-slate-200">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1">Workflow</div>
          <div className="text-sm font-semibold text-slate-800 mb-2">{flowName || 'Untitled flow'}</div>
          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${flowEnabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-500'}`}>
            {flowEnabled ? '\u25cf Active' : '\u25cb Inactive'}
          </span>
        </div>

        {/* Trigger info */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2">Trigger</div>
          {triggerNode ? (
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-emerald-100 flex items-center justify-center text-emerald-600">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <div className="text-sm font-medium text-slate-700">{triggerNode.data?.label || 'Configured'}</div>
                <div className="text-[10px] text-slate-400">{triggerNode.data?.source} / {triggerNode.data?.event}</div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-400 italic">No trigger configured &mdash; click the trigger node</div>
          )}
        </div>

        {/* Node counts */}
        <div className="grid grid-cols-3 gap-2">
          <div className="p-3 rounded-xl border border-blue-100 bg-blue-50 text-center">
            <div className="text-lg font-bold text-blue-600">{actionCount}</div>
            <div className="text-[10px] font-medium text-blue-500">Actions</div>
          </div>
          <div className="p-3 rounded-xl border border-amber-100 bg-amber-50 text-center">
            <div className="text-lg font-bold text-amber-600">{conditionCount}</div>
            <div className="text-[10px] font-medium text-amber-500">Conditions</div>
          </div>
          <div className="p-3 rounded-xl border border-violet-100 bg-violet-50 text-center">
            <div className="text-lg font-bold text-violet-600">{delayCount}</div>
            <div className="text-[10px] font-medium text-violet-500">Delays</div>
          </div>
        </div>

        {/* Stats */}
        {(flowStat.triggers > 0 || flowStat.messages_sent > 0) && (
          <div className="p-4 rounded-xl border border-slate-200 bg-white">
            <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2">Statistics</div>
            <div className="space-y-1.5">
              {flowStat.triggers > 0 && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-500">Triggers</span>
                  <span className="font-semibold text-blue-600">{flowStat.triggers.toLocaleString()}</span>
                </div>
              )}
              {flowStat.messages_sent > 0 && (
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-500">Messages sent</span>
                  <span className="font-semibold text-emerald-600">{flowStat.messages_sent.toLocaleString()}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Validation */}
        <div className={`p-4 rounded-xl border ${totalErrors > 0 ? 'border-rose-200 bg-rose-50' : 'border-emerald-200 bg-emerald-50'}`}>
          <div className={`text-xs font-bold uppercase tracking-widest mb-2 ${totalErrors > 0 ? 'text-rose-600' : 'text-emerald-600'}`}>
            {totalErrors > 0 ? `\u26a0 ${nodeErrors} issue${nodeErrors !== 1 ? 's' : ''} found` : '\u2713 Flow looks good'}
          </div>
          {totalErrors > 0 ? (
            <div className="space-y-1">
              {Array.from(validationErrors.entries())
                .filter(([id]) => (nodes || []).some(n => n.id === id))
                .slice(0, 6)
                .map(([id, errs]) => {
                  const n = (nodes || []).find(nd => nd.id === id);
                  return (
                    <div key={id} className="text-[11px] text-rose-700 flex items-start gap-1.5">
                      <span className="text-rose-400 mt-0.5">{'\u2022'}</span>
                      <span>
                        <span className="font-semibold">{n?.data?.actionLabel || n?.data?.label || n?.type || 'Node'}:</span>{' '}
                        {errs[0]}
                      </span>
                    </div>
                  );
                })}
            </div>
          ) : (
            <div className="text-xs text-emerald-600">All nodes are properly configured and connected.</div>
          )}
        </div>

        {/* Last Run Status */}
        {lastRunStatus && Object.keys(lastRunStatus).length > 0 && (() => {
          const entries = Object.entries(lastRunStatus);
          const successCount = entries.filter(([, v]) => v?.status === 'success').length;
          const errorCount = entries.filter(([, v]) => v?.status === 'error').length;
          const lastTs = entries.map(([, v]) => v?.timestamp).filter(Boolean).sort().pop();
          const allSuccess = errorCount === 0 && successCount > 0;
          return (
            <div className={`p-4 rounded-xl border ${allSuccess ? 'border-emerald-200 bg-emerald-50' : 'border-rose-200 bg-rose-50'}`}>
              <div className={`text-xs font-bold uppercase tracking-widest mb-2 ${allSuccess ? 'text-emerald-600' : 'text-rose-600'}`}>
                Last Run
              </div>
              <div className="flex items-center gap-2 mb-2">
                {allSuccess
                  ? <><CheckCircle2 className="w-4 h-4 text-emerald-500" /><span className="text-sm font-semibold text-emerald-700">All nodes succeeded</span></>
                  : <><XCircle className="w-4 h-4 text-rose-500" /><span className="text-sm font-semibold text-rose-700">{errorCount} node{errorCount !== 1 ? 's' : ''} failed</span></>
                }
              </div>
              {errorCount > 0 && (
                <div className="space-y-1 mb-2">
                  {entries.filter(([, v]) => v?.status === 'error').slice(0, 4).map(([nodeId, v]) => {
                    const n = (nodes || []).find(nd => nd.id === nodeId);
                    return (
                      <div key={nodeId} className="text-[11px] text-rose-700 flex items-start gap-1.5">
                        <XCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                        <span><span className="font-semibold">{n?.data?.actionLabel || n?.data?.label || 'Node'}:</span> {v?.message || 'Error'}</span>
                      </div>
                    );
                  })}
                </div>
              )}
              {lastTs && <div className="text-[10px] text-slate-400 flex items-center gap-1"><Clock className="w-3 h-3" /> {new Date(lastTs).toLocaleString()}</div>}
            </div>
          );
        })()}

        {/* Tips */}
        <div className="p-4 rounded-xl border border-slate-200 bg-slate-50">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2">Quick Tips</div>
          <div className="space-y-1.5 text-[11px] text-slate-500">
            <div>{'\u2022'} Click the <span className="font-semibold text-blue-600">+</span> button on any connection to insert a step</div>
            <div>{'\u2022'} Drag from a node handle to another to create a connection</div>
            <div>{'\u2022'} Click any node to edit its settings</div>
            <div>{'\u2022'} Invalid connections are automatically prevented</div>
          </div>
        </div>
      </div>
    </>
  );
}
