import React from 'react';
import { ShoppingCart, MessageSquare, ScanLine, Activity } from 'lucide-react';

export default function Sidebar({ onOpenNew }) {
  const onDragStart = (event, nodeType, preset) => {
    event.dataTransfer.setData('application/reactflow', nodeType);
    event.dataTransfer.setData('application/preset', JSON.stringify(preset));
    event.dataTransfer.effectAllowed = 'move';
  };

  const draggables = [
    { type: 'triggerNode', label: 'Shopify Event', icon: <ShoppingCart className="w-4 h-4" />, preset: { triggerSource: 'shopify', shopifyTopicPreset: 'orders/paid' } },
    { type: 'triggerNode', label: 'WhatsApp Message', icon: <MessageSquare className="w-4 h-4" />, preset: { triggerSource: 'whatsapp', waTriggerMode: 'incoming' } },
    { type: 'triggerNode', label: 'Delivery Status', icon: <ScanLine className="w-4 h-4" />, preset: { triggerSource: 'delivery' } },
    { type: 'triggerNode', label: 'Retargeting Job', icon: <Activity className="w-4 h-4" />, preset: { triggerSource: 'retargeting' } }
  ];

  return (
    <aside className="w-64 bg-white border-l border-slate-200 h-[calc(100vh-48px)] flex flex-col pt-4 px-4 overflow-y-auto">
      <div className="mb-4">
        <h2 className="text-sm font-semibold text-slate-800">Add Automation</h2>
        <p className="text-xs text-slate-500 mt-1">Drag and drop a trigger onto the canvas, or click to add directly.</p>
      </div>
      
      <div className="flex flex-col gap-3">
        {draggables.map((item, idx) => (
          <div
            key={idx}
            className="flex items-center gap-3 p-3 border border-slate-200 rounded-lg bg-slate-50 cursor-grab hover:bg-slate-100 hover:border-slate-300 transition-colors"
            onDragStart={(event) => onDragStart(event, item.type, item.preset)}
            onClick={() => onOpenNew && onOpenNew(item.preset)}
            draggable
          >
            <div className="p-1.5 bg-white shadow-sm rounded">
              {item.icon}
            </div>
            <span className="text-sm font-medium text-slate-700">{item.label}</span>
          </div>
        ))}
      </div>

      <div className="mt-8 pt-4 border-t border-slate-100">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Controls</h3>
        <p className="text-[11px] text-slate-400 mb-2">• Scroll to pan or zoom</p>
        <p className="text-[11px] text-slate-400 mb-2">• Drag nodes to rearrange</p>
        <p className="text-[11px] text-slate-400 mb-2">• Click a node to open settings</p>
      </div>
    </aside>
  );
}
