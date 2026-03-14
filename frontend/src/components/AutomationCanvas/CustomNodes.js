import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { ShoppingCart, MessageSquare, ScanLine, Tag, Activity, Plus } from 'lucide-react';

const ICON_MAP = {
  shopify: <ShoppingCart className="w-5 h-5 text-green-500" />,
  whatsapp: <MessageSquare className="w-5 h-5 text-emerald-500" />,
  delivery: <ScanLine className="w-5 h-5 text-blue-500" />,
  retargeting: <Activity className="w-5 h-5 text-purple-500" />,
};

const getTriggerIcon = (source) => ICON_MAP[source] || ICON_MAP.whatsapp;

export const TriggerNode = ({ data }) => {
  const source = data?.rule?.trigger?.source || 'whatsapp';
  const event = data?.rule?.trigger?.event || 'incoming_message';
  
  return (
    <div 
      className="bg-white rounded-xl shadow-[0_4px_20px_-4px_rgba(0,0,0,0.1)] border border-slate-200 p-4 min-w-[260px] cursor-pointer hover:border-blue-400 transition-colors"
      onClick={() => data.onEdit && data.onEdit(data.rule)}
    >
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 bg-slate-50 rounded-lg">
          {getTriggerIcon(source)}
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-800 capitalize leading-tight">{source}</h3>
          <p className="text-xs text-slate-500">{event}</p>
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between">
        <span className="inline-flex items-center px-2 py-1 rounded bg-slate-100 text-[10px] font-medium text-slate-600">
          Trigger Phase
        </span>
        <button 
          onClick={(e) => {
            e.stopPropagation();
            if (data.onAddStep) data.onAddStep(e, data.rule);
          }}
          className="p-1.5 rounded-full bg-blue-50 text-blue-600 hover:bg-blue-100 hover:scale-110 transition-all shadow-sm group"
          title="Add next step"
        >
          <Plus className="w-4 h-4" />
        </button>
      </div>
      <Handle type="source" position={Position.Right} className="w-3 h-3 bg-blue-500 opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
};

export const ActionNode = ({ data }) => {
  const rule = data?.rule;
  const actions = rule?.actions || [];
  const primaryAction = actions[0]?.type || 'send_text';

  return (
    <div 
      className="bg-white rounded-xl shadow-[0_4px_20px_-4px_rgba(0,0,0,0.1)] border border-slate-200 p-4 min-w-[260px] cursor-pointer hover:border-blue-400 transition-colors"
      onClick={() => data.onEdit && data.onEdit(data.rule)}
    >
      <Handle type="target" position={Position.Left} className="w-3 h-3 bg-blue-500" />
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 bg-slate-50 rounded-lg">
          <MessageSquare className="w-5 h-5 text-blue-500" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-800 leading-tight">Action</h3>
          <p className="text-xs text-slate-500 truncate max-w-[150px]">{primaryAction.replace(/_/g, ' ')}</p>
        </div>
      </div>
      
      <div className="mt-3 pt-3 border-t border-slate-100 flex flex-col gap-1">
        <div className="text-xs font-semibold text-slate-700 capitalize">{rule?.name || 'Untitled Rule'}</div>
        <div className="flex items-center justify-between">
          <span className={`text-[10px] font-medium px-2 py-0.5 rounded ${rule?.enabled ? 'bg-emerald-50 text-emerald-600' : 'bg-rose-50 text-rose-600'}`}>
            {rule?.enabled ? 'Active' : 'Inactive'}
          </span>
          {actions.length > 1 && (
            <span className="text-[10px] text-slate-400">+{actions.length - 1} more</span>
          )}
        </div>
      </div>
    </div>
  );
};

export const nodeTypes = {
  triggerNode: TriggerNode,
  actionNode: ActionNode,
};
