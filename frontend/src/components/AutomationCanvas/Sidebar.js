import React from 'react';
import { ShoppingCart, MessageSquare, ScanLine, Activity } from 'lucide-react';

export default function Sidebar({ onOpenNew }) {
  const onDragStart = (event, nodeType, preset) => {
    event.dataTransfer.setData('application/reactflow', nodeType);
    event.dataTransfer.setData('application/preset', JSON.stringify(preset));
    event.dataTransfer.effectAllowed = 'move';
  };

  const draggables = [
    { type: 'triggerNode', label: 'Shopify', desc: 'Orders, fulfillments, etc.', icon: <ShoppingCart className="w-5 h-5 text-green-500" />, preset: { triggerSource: 'shopify', shopifyTopicPreset: 'orders/paid', name: '' } },
    { type: 'triggerNode', label: 'WhatsApp', desc: 'Incoming messages & replies', icon: <MessageSquare className="w-5 h-5 text-emerald-500" />, preset: { triggerSource: 'whatsapp', waTriggerMode: 'incoming', name: '' } },
    { type: 'triggerNode', label: 'Delivery', desc: 'Carrier status updates', icon: <ScanLine className="w-5 h-5 text-blue-500" />, preset: { triggerSource: 'delivery', name: '' } },
    { type: 'triggerNode', label: 'Retargeting', desc: 'Bulk audience campaigns', icon: <Activity className="w-5 h-5 text-purple-500" />, preset: { triggerSource: 'retargeting', name: '' } }
  ];

  return (
    <aside className="w-72 bg-white border-l border-slate-200 h-[calc(100vh-48px)] flex flex-col pt-4 px-4 overflow-y-auto">
      <div className="mb-6">
        <h2 className="text-base font-semibold text-slate-800 mb-1">Triggers</h2>
        <p className="text-xs text-slate-500">Select an app or service that starts your automation.</p>
      </div>
      
      <div className="flex flex-col gap-3">
        {draggables.map((item, idx) => (
          <div
            key={idx}
            className="flex items-center gap-3 p-3 border border-slate-200 rounded-lg bg-white shadow-sm cursor-grab hover:border-blue-400 hover:shadow transition-all group"
            onDragStart={(event) => onDragStart(event, item.type, item.preset)}
            onClick={() => onOpenNew && onOpenNew(item.preset)}
            draggable
          >
            <div className="p-2 bg-slate-50 border border-slate-100 rounded-lg flex items-center justify-center">
              {item.icon}
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-700">{item.label}</div>
              <div className="text-[11px] text-slate-500">{item.desc}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-8 pt-4 border-t border-slate-100">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Controls</h3>
        <p className="text-[11px] text-slate-400 mb-2">• Scroll to pan or zoom</p>
        <p className="text-[11px] text-slate-400 mb-2">• Drag nodes to rearrange</p>
        <p className="text-[11px] text-slate-400 mb-2">• Click a node to pick an event</p>
      </div>
    </aside>
  );
}
