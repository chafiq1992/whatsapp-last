import React, { useState, useCallback, useMemo, useEffect } from 'react';
import {
  ReactFlow, ReactFlowProvider, Background, Controls, MiniMap,
  applyNodeChanges, applyEdgeChanges, MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { flowNodeTypes } from './FlowNodes';
import api from '../../api';
import {
  Save, Power, PowerOff, Plus, Trash2, ArrowLeft,
  ShoppingCart, MessageSquare, ScanLine, Zap,
  SplitSquareHorizontal, Timer, Ban,
  ChevronRight, X,
} from 'lucide-react';

/* ═══════════════════════════════════════════════════════════
   Trigger / Action / Condition catalogs
   (mirroring the variables & templates from AutomationStudio)
   ═══════════════════════════════════════════════════════════ */
const SHOPIFY_EVENTS = [
  { id: 'orders/paid',           label: 'Order Paid',              variables: ['id','order_number','total_price','customer.phone','customer.first_name','created_at'] },
  { id: 'orders/create',         label: 'New Order Created',       variables: ['id','order_number','financial_status','total_price','customer.phone','customer.first_name','line_items[].title','shipping_address.city'] },
  { id: 'fulfillments/create',   label: 'Fulfillment Created',     variables: ['tracking','customer.phone','customer.first_name'] },
  { id: 'customers/create',      label: 'New Customer',            variables: ['id','email','first_name','last_name','phone','default_address.city'] },
  { id: 'checkouts/update',      label: 'Abandoned Checkout',      variables: ['id','abandoned_checkout_url','email','phone','total_price','line_items[].title'] },
  { id: 'draft_orders/create',   label: 'Draft Order Created',     variables: ['id','name','invoice_url','status','total_price','customer.phone','customer.first_name'] },
];

const WHATSAPP_EVENTS = [
  { id: 'message',     label: 'Incoming Message',  mode: 'incoming' },
  { id: 'no_reply',    label: 'No Agent Reply',    mode: 'no_reply' },
  { id: 'interactive', label: 'Button Clicked',    mode: 'button'   },
];

const ACTION_CATALOG = [
  { id: 'send_text',     label: 'Send Text Message',       icon: <MessageSquare className="w-4 h-4 text-blue-500" />,   type: 'send_whatsapp_text' },
  { id: 'send_template', label: 'Send WhatsApp Template',  icon: <MessageSquare className="w-4 h-4 text-emerald-500" />, type: 'send_whatsapp_template' },
  { id: 'tag_customer',  label: 'Tag Customer (Shopify)',   icon: <Zap className="w-4 h-4 text-amber-500" />,            type: 'shopify_tag' },
  { id: 'exit',          label: 'Stop / Exit',              icon: <Ban className="w-4 h-4 text-rose-500" />,             type: 'exit' },
];

/* ═══════════════════════════════════════════════════════════
   Pre-built flow templates (one-click install)
   ═══════════════════════════════════════════════════════════ */
const FLOW_TEMPLATES = [
  {
    id: 'tpl_order_confirm',
    label: 'Order Confirmation',
    description: 'Send a WhatsApp template when an order is paid',
    build: () => buildTemplateFlow('orders/paid', 'Order Paid', 'send_template', 'Send WhatsApp Template', 'order_confirmed'),
  },
  {
    id: 'tpl_vip_tag',
    label: 'Tag VIP Customers',
    description: 'Tag customers who spend more than a threshold',
    build: () => {
      const triggerId = 'n_' + Date.now() + '_1';
      const condId = 'n_' + Date.now() + '_2';
      const actionId = 'n_' + Date.now() + '_3';
      const addId = 'n_' + Date.now() + '_4';
      return {
        nodes: [
          rfNode(triggerId, 'startTrigger', 0, 0, { configured: true, source: 'shopify', label: 'Order Paid', event: 'orders/paid', description: 'Shopify: orders/paid' }),
          rfNode(condId, 'conditionFlow', 0, 200, { expression: 'total_price > 500', trueLabel: 'VIP', falseLabel: 'Skip', field: 'total_price', operator: '>', value: '500' }),
          rfNode(actionId, 'actionFlow', -120, 420, { actionType: 'send_text', actionLabel: 'Send Text Message', text: 'مرحبا! أنت عميل VIP 🌟', description: 'Send VIP welcome text' }),
          rfNode(addId, 'addStep', 120, 420, {}),
        ],
        edges: [
          rfEdge(triggerId, condId),
          rfEdge(condId, actionId, 'true'),
          rfEdge(condId, addId, 'false'),
        ],
        meta: { name: 'Tag VIP Customers' },
      };
    },
  },
  {
    id: 'tpl_abandoned_cart',
    label: 'Abandoned Cart Recovery',
    description: 'Send a reminder when a checkout is abandoned',
    build: () => buildTemplateFlow('checkouts/update', 'Abandoned Checkout', 'send_template', 'Send WhatsApp Template', 'abandoned_cart_reminder'),
  },
];

function buildTemplateFlow(event, trigLabel, actionId, actionLabel, templateName) {
  const tId = 'n_' + Date.now() + '_1';
  const aId = 'n_' + Date.now() + '_2';
  const addId = 'n_' + Date.now() + '_3';
  return {
    nodes: [
      rfNode(tId, 'startTrigger', 0, 0, { configured: true, source: 'shopify', label: trigLabel, event, description: `Shopify: ${event}` }),
      rfNode(aId, 'actionFlow', 0, 200, { actionType: actionId === 'send_template' ? 'send_whatsapp_template' : 'send_whatsapp_text', actionLabel, templateName: templateName || '', description: `Template: ${templateName || '(select)'}` }),
      rfNode(addId, 'addStep', 0, 400, {}),
    ],
    edges: [
      rfEdge(tId, aId),
      rfEdge(aId, addId),
    ],
    meta: { name: trigLabel + ' Automation' },
  };
}

/* ═══════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════ */
let _seq = 1;
const uid = () => 'fn_' + Date.now().toString(36) + '_' + (_seq++);

function rfNode(id, type, x, y, data) {
  return { id, type, position: { x, y }, data, draggable: true };
}
function rfEdge(source, target, sourceHandle, label) {
  return {
    id: `e_${source}_${target}_${sourceHandle || 'default'}`,
    source, target,
    ...(sourceHandle ? { sourceHandle } : {}),
    type: 'smoothstep',
    animated: true,
    style: { stroke: '#94a3b8', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#94a3b8' },
    ...(label ? { label } : {}),
  };
}

/* ═══════════════════════════════════════════════════════════
   Saved flows list — shows existing flows created in this tab
   ═══════════════════════════════════════════════════════════ */
function FlowsListView({ flows, onSelect, onNewFlow, onDelete, loading }) {
  return (
    <div className="h-full flex flex-col bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-slate-50 via-white to-indigo-50">
      {/* Header bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b bg-white/80 backdrop-blur">
        <div>
          <h2 className="text-xl font-bold text-slate-800">Flows</h2>
          <p className="text-sm text-slate-500">Visual workflows powered by your automations</p>
        </div>
        <button
          className="px-6 py-2.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all flex items-center gap-2"
          onClick={onNewFlow}
        >
          <Plus className="w-4 h-4" /> Create workflow
        </button>
      </div>

      {/* Template gallery */}
      <div className="px-6 py-4 border-b bg-slate-50/50">
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3">Quick start templates</div>
        <div className="flex gap-3 overflow-x-auto pb-1">
          {FLOW_TEMPLATES.map((tpl) => (
            <button
              key={tpl.id}
              className="flex-shrink-0 w-56 p-4 rounded-xl border border-slate-200 bg-white hover:border-blue-300 hover:shadow-md transition-all text-left group"
              onClick={() => onSelect(null, tpl)}
            >
              <div className="text-sm font-semibold text-slate-700 mb-1 group-hover:text-blue-600 transition-colors">{tpl.label}</div>
              <div className="text-xs text-slate-400">{tpl.description}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Flow list */}
      <div className="flex-1 overflow-auto px-6 py-4">
        {loading ? (
          <div className="text-sm text-slate-500">Loading…</div>
        ) : (flows || []).length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 text-slate-400">
            <Zap className="w-12 h-12 text-slate-300" />
            <div className="text-center">
              <div className="text-lg font-semibold text-slate-500">No flows yet</div>
              <div className="text-sm">Create your first workflow or start from a template above</div>
            </div>
          </div>
        ) : (
          <div className="grid gap-3 max-w-4xl">
            {flows.map((f) => (
              <div
                key={f.id}
                className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between hover:border-blue-300 hover:shadow-sm transition-all cursor-pointer group"
                onClick={() => onSelect(f)}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <div className="text-sm font-semibold text-slate-800 group-hover:text-blue-600 transition-colors truncate">{f.name || f.id}</div>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${f.enabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-500'}`}>
                      {f.enabled ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1 truncate">
                    Trigger: {f.trigger?.source || 'whatsapp'} / {f.trigger?.event || 'incoming'}
                  </div>
                </div>
                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  <button
                    className="p-2 rounded-lg text-rose-400 hover:bg-rose-50 hover:text-rose-600 transition-colors"
                    onClick={() => onDelete(f.id)}
                    title="Delete flow"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  <ChevronRight className="w-5 h-5 text-slate-300 group-hover:text-blue-400 transition-colors" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   MAIN FlowBuilder component
   ═══════════════════════════════════════════════════════════ */
function FlowBuilderCanvas({ initialFlow, templates, onBack, onSaveToBackend, allRules }) {
  const [nodes, setNodes] = useState(initialFlow?.nodes || []);
  const [edges, setEdges] = useState(initialFlow?.edges || []);
  const [flowName, setFlowName] = useState(initialFlow?.meta?.name || '');
  const [flowEnabled, setFlowEnabled] = useState(initialFlow?.meta?.enabled !== false);
  const [flowId, setFlowId] = useState(initialFlow?.meta?.ruleId || '');
  const [saving, setSaving] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [sidePanel, setSidePanel] = useState(null); // 'trigger_picker' | 'step_picker' | 'node_editor'
  const [addAfterNodeId, setAddAfterNodeId] = useState(null);

  const selectedNode = useMemo(() => nodes.find(n => n.id === selectedNodeId), [nodes, selectedNodeId]);

  const onNodesChange = useCallback((changes) => setNodes(nds => applyNodeChanges(changes, nds)), []);
  const onEdgesChange = useCallback((changes) => setEdges(eds => applyEdgeChanges(changes, eds)), []);

  /* ── Node callbacks (injected into node data) ─────────── */
  const onTriggerSelect = useCallback(() => setSidePanel('trigger_picker'), []);

  const onAddStepClick = useCallback((nodeId) => {
    setAddAfterNodeId(nodeId);
    setSidePanel('step_picker');
  }, []);

  const onNodeSelect = useCallback((nodeId) => {
    setSelectedNodeId(nodeId);
    const n = nodes.find(nd => nd.id === nodeId);
    if (n && n.type !== 'addStep') {
      setSidePanel('node_editor');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes]);

  /* Inject callbacks into nodes */
  const nodesWithCallbacks = useMemo(() => {
    return nodes.map(n => ({
      ...n,
      data: {
        ...n.data,
        onSelect: () => {
          if (n.type === 'startTrigger' && !n.data.configured) {
            onTriggerSelect();
          } else if (n.type === 'addStep') {
            onAddStepClick(n.id);
          } else {
            onNodeSelect(n.id);
          }
        },
        onAdd: () => onAddStepClick(n.id),
      },
    }));
  }, [nodes, onTriggerSelect, onAddStepClick, onNodeSelect]);

  /* ── Adding steps to the flow ────────────────────────── */
  const addStepToFlow = useCallback((stepType, config = {}) => {
    const parentId = addAfterNodeId;
    if (!parentId) return;

    const parentNode = nodes.find(n => n.id === parentId);
    if (!parentNode) return;

    const newId = uid();
    const addBtnId = uid();
    const px = parentNode.position.x;
    const py = parentNode.position.y;

    let newNode;
    if (stepType === 'condition') {
      newNode = rfNode(newId, 'conditionFlow', px, py + 60, {
        expression: config.expression || '',
        trueLabel: config.trueLabel || 'Then',
        falseLabel: config.falseLabel || 'Otherwise',
        field: config.field || '',
        operator: config.operator || '==',
        value: config.value || '',
      });
      const addTrue = rfNode(uid(), 'addStep', px - 120, py + 280, {});
      const addFalse = rfNode(uid(), 'addStep', px + 120, py + 280, {});

      setNodes(prev => {
        const without = prev.filter(n => n.id !== parentId);
        return [...without, newNode, addTrue, addFalse];
      });
      setEdges(prev => {
        // Remove old edges to addStep parent
        const clean = prev.filter(e => e.target !== parentId);
        // Find edge coming INTO the addStep
        const incomingEdge = prev.find(e => e.target === parentId);
        const sourceNode = incomingEdge?.source;
        const sourceHandle = incomingEdge?.sourceHandle;
        const newEdges = [];
        if (sourceNode) {
          newEdges.push(rfEdge(sourceNode, newId, sourceHandle));
        }
        newEdges.push(rfEdge(newId, addTrue.id, 'true', '✓ Yes'));
        newEdges.push(rfEdge(newId, addFalse.id, 'false', '✗ No'));
        return [...clean, ...newEdges];
      });
    } else if (stepType === 'delay') {
      newNode = rfNode(newId, 'delayFlow', px, py + 60, { minutes: config.minutes || 10 });
      const addBtn = rfNode(addBtnId, 'addStep', px, py + 260, {});
      setNodes(prev => {
        const without = prev.filter(n => n.id !== parentId);
        return [...without, newNode, addBtn];
      });
      setEdges(prev => {
        const clean = prev.filter(e => e.target !== parentId);
        const incomingEdge = prev.find(e => e.target === parentId);
        const sourceNode = incomingEdge?.source;
        const sourceHandle = incomingEdge?.sourceHandle;
        const newEdges = [];
        if (sourceNode) newEdges.push(rfEdge(sourceNode, newId, sourceHandle));
        newEdges.push(rfEdge(newId, addBtnId));
        return [...clean, ...newEdges];
      });
    } else {
      // Action node
      const actionType = config.type || 'send_whatsapp_text';
      const actionCat = ACTION_CATALOG.find(a => a.type === actionType) || ACTION_CATALOG[0];
      newNode = rfNode(newId, 'actionFlow', px, py + 60, {
        actionType,
        actionLabel: actionCat.label,
        text: config.text || '',
        templateName: config.templateName || '',
        templateLanguage: config.templateLanguage || 'en',
        tag: config.tag || '',
        description: config.description || '',
      });
      const addBtn = rfNode(addBtnId, 'addStep', px, py + 260, {});
      setNodes(prev => {
        const without = prev.filter(n => n.id !== parentId);
        return [...without, newNode, addBtn];
      });
      setEdges(prev => {
        const clean = prev.filter(e => e.target !== parentId);
        const incomingEdge = prev.find(e => e.target === parentId);
        const sourceNode = incomingEdge?.source;
        const sourceHandle = incomingEdge?.sourceHandle;
        const newEdges = [];
        if (sourceNode) newEdges.push(rfEdge(sourceNode, newId, sourceHandle));
        if (actionType !== 'exit') {
          newEdges.push(rfEdge(newId, addBtnId));
        }
        return [...clean, ...newEdges];
      });
    }

    setSidePanel(null);
    setAddAfterNodeId(null);
  }, [addAfterNodeId, nodes]);

  /* ── Configure trigger ──────────────────────────────── */
  const configureTrigger = useCallback((source, event, label) => {
    const triggerNode = nodes.find(n => n.type === 'startTrigger');
    if (!triggerNode) return;
    setNodes(prev => prev.map(n => {
      if (n.id !== triggerNode.id) return n;
      return {
        ...n,
        data: {
          ...n.data,
          configured: true,
          source,
          event,
          label,
          description: `${source}: ${event}`,
        },
      };
    }));
    // Add an addStep button below the trigger if not already present
    const hasChildEdge = edges.some(e => e.source === triggerNode.id);
    if (!hasChildEdge) {
      const addId = uid();
      const addNode = rfNode(addId, 'addStep', triggerNode.position.x, triggerNode.position.y + 200, {});
      setNodes(prev => [...prev, addNode]);
      setEdges(prev => [...prev, rfEdge(triggerNode.id, addId)]);
    }
    setSidePanel(null);
  }, [nodes, edges]);

  /* ── Update node data ───────────────────────────────── */
  const updateNodeData = useCallback((nodeId, patch) => {
    setNodes(prev => prev.map(n => {
      if (n.id !== nodeId) return n;
      return { ...n, data: { ...n.data, ...patch } };
    }));
  }, []);

  /* ── Delete a node ──────────────────────────────────── */
  const deleteNode = useCallback((nodeId) => {
    const node = nodes.find(n => n.id === nodeId);
    if (!node || node.type === 'startTrigger') return;

    // Find all descendant nodes to remove
    const toRemove = new Set([nodeId]);
    const findDescendants = (id) => {
      edges.filter(e => e.source === id).forEach(e => {
        toRemove.add(e.target);
        findDescendants(e.target);
      });
    };
    findDescendants(nodeId);

    // Find parent and reconnect with an addStep
    const incomingEdge = edges.find(e => e.target === nodeId);
    const parentId = incomingEdge?.source;
    const parentHandle = incomingEdge?.sourceHandle;

    const addId = uid();
    // eslint-disable-next-line no-unused-vars
    const parentNode = parentId ? nodes.find(n => n.id === parentId) : null;
    const addNode = rfNode(addId, 'addStep', node.position.x, node.position.y, {});

    setNodes(prev => [...prev.filter(n => !toRemove.has(n.id)), addNode]);
    setEdges(prev => {
      const cleaned = prev.filter(e => !toRemove.has(e.source) && !toRemove.has(e.target));
      if (parentId) {
        return [...cleaned, rfEdge(parentId, addId, parentHandle)];
      }
      return cleaned;
    });
    setSidePanel(null);
    setSelectedNodeId(null);
  }, [nodes, edges]);

  /* ═══════════════════════════════════════════════════════
     Convert flow graph → automation rule JSON
     ═══════════════════════════════════════════════════════ */
  const flowToRule = useCallback(() => {
    const triggerNode = nodes.find(n => n.type === 'startTrigger' && n.data.configured);
    if (!triggerNode) return null;

    const source = triggerNode.data.source || 'whatsapp';
    const event = triggerNode.data.event || 'message';

    const trigger = { source };
    if (source === 'shopify') {
      trigger.event = event;
    } else if (source === 'whatsapp') {
      trigger.event = event;
    } else if (source === 'delivery') {
      trigger.event = event || 'status_change';
    }

    // Walk the graph from trigger to collect condition & actions
    let condition = {};
    const actions = [];
    const ws = (() => { try { return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase(); } catch { return 'irranova'; } })();

    const collectActions = (nodeId, visited = new Set()) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      const outEdges = edges.filter(e => e.source === nodeId);
      for (const edge of outEdges) {
        const target = nodes.find(n => n.id === edge.target);
        if (!target || target.type === 'addStep') continue;

        if (target.type === 'conditionFlow') {
          const d = target.data;
          const field = String(d.field || '').trim();
          const op = String(d.operator || '==').trim();
          const val = String(d.value || '').trim();
          if (field) {
            condition = {
              match: 'expression',
              expression: `{{ ${field} }} ${op} ${val}`,
              field, operator: op, value: val,
            };
          }
          // Follow the "true" branch for actions
          collectActions(target.id, visited);
        } else if (target.type === 'delayFlow') {
          actions.push({ type: 'delay', minutes: Number(target.data.minutes || 10) });
          collectActions(target.id, visited);
        } else if (target.type === 'actionFlow') {
          const d = target.data;
          const at = d.actionType || 'send_whatsapp_text';
          if (at === 'send_whatsapp_text') {
            actions.push({ type: 'send_whatsapp_text', to: '{{ phone }}', text: d.text || '' });
          } else if (at === 'send_whatsapp_template') {
            const comps = [];
            actions.push({
              type: 'send_whatsapp_template',
              to: '{{ phone }}',
              template_name: d.templateName || '',
              language: d.templateLanguage || 'en',
              components: comps,
            });
          } else if (at === 'shopify_tag') {
            actions.push({ type: 'add_tag', tag: d.tag || '' });
          } else if (at === 'exit') {
            actions.push({ type: 'exit' });
          }
          collectActions(target.id, visited);
        }
      }
    };
    collectActions(triggerNode.id);

    if (!actions.length) {
      actions.push({ type: 'send_whatsapp_text', to: '{{ phone }}', text: '' });
    }

    const rule = {
      id: flowId || `flow_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      name: flowName || 'Untitled Flow',
      enabled: flowEnabled,
      workspaces: [ws],
      trigger,
      condition,
      actions,
      meta: { created_by: 'flow_builder', flow_graph: { nodes: nodes.map(n => ({ ...n, data: { ...n.data, onSelect: undefined, onAdd: undefined } })), edges } },
    };
    return rule;
  }, [nodes, edges, flowName, flowEnabled, flowId]);

  /* ── Save flow ──────────────────────────────────────── */
  const saveFlow = useCallback(async (enable) => {
    if (enable !== undefined) setFlowEnabled(enable);
    const rule = flowToRule();
    if (!rule) { alert('Please configure a trigger first.'); return; }
    if (enable !== undefined) rule.enabled = enable;

    setSaving(true);
    try {
      await onSaveToBackend(rule, flowId);
      setFlowId(rule.id);
    } catch (e) {
      alert(e?.response?.data?.detail || 'Failed to save flow.');
    } finally {
      setSaving(false);
    }
  }, [flowToRule, flowId, onSaveToBackend]);

  /* ═══════════════════════════════════════════════════════
     RENDER
     ═══════════════════════════════════════════════════════ */
  return (
    <div className="flex flex-col h-full w-full bg-slate-50">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b bg-white/90 backdrop-blur z-10 gap-3">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <button
            className="p-2 rounded-lg hover:bg-slate-100 text-slate-500 transition-colors"
            onClick={onBack}
            title="Back to flows"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <input
            className="text-base font-semibold text-slate-800 border-none bg-transparent focus:outline-none focus:ring-0 min-w-0 flex-1 placeholder-slate-300"
            value={flowName}
            onChange={(e) => setFlowName(e.target.value)}
            placeholder="Untitled flow…"
          />
        </div>
        <div className="flex items-center gap-2">
          <button
            className="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 bg-white hover:bg-slate-50 transition-colors flex items-center gap-2 disabled:opacity-50"
            onClick={() => saveFlow()}
            disabled={saving}
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving…' : 'Save draft'}
          </button>
          <button
            className={`px-4 py-2 rounded-lg text-sm font-semibold text-white flex items-center gap-2 transition-all disabled:opacity-50 ${
              flowEnabled
                ? 'bg-gradient-to-r from-rose-500 to-rose-600 hover:from-rose-600 hover:to-rose-700 shadow-rose-200'
                : 'bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 shadow-emerald-200'
            } shadow-lg`}
            onClick={() => saveFlow(!flowEnabled)}
            disabled={saving}
          >
            {flowEnabled ? <><PowerOff className="w-4 h-4" /> Turn off</> : <><Power className="w-4 h-4" /> Turn on workflow</>}
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* React Flow Canvas */}
        <div className="flex-1 h-full">
          <ReactFlow
            nodes={nodesWithCallbacks}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={flowNodeTypes}
            fitView
            fitViewOptions={{ padding: 0.4 }}
            minZoom={0.3}
            maxZoom={1.5}
            onPaneClick={() => { setSidePanel(null); setSelectedNodeId(null); }}
          >
            <Background color="#e2e8f0" gap={20} size={1} />
            <Controls className="bg-white shadow-xl border border-slate-200 rounded-lg overflow-hidden" />
            <MiniMap
              nodeColor={(n) => {
                if (n.type === 'startTrigger') return '#10b981';
                if (n.type === 'conditionFlow') return '#f59e0b';
                if (n.type === 'actionFlow') return '#3b82f6';
                if (n.type === 'delayFlow') return '#8b5cf6';
                return '#cbd5e1';
              }}
              maskColor="rgba(248, 250, 252, 0.8)"
              className="border border-slate-200 rounded-lg shadow-sm"
            />
          </ReactFlow>
        </div>

        {/* Side Panel */}
        {sidePanel && (
          <div className="w-80 h-full border-l bg-white overflow-y-auto shadow-xl animate-slide-in-right flex flex-col">
            {sidePanel === 'trigger_picker' && (
              <TriggerPickerPanel
                onClose={() => setSidePanel(null)}
                onSelectTrigger={configureTrigger}
              />
            )}
            {sidePanel === 'step_picker' && (
              <StepPickerPanel
                onClose={() => { setSidePanel(null); setAddAfterNodeId(null); }}
                onAddStep={addStepToFlow}
              />
            )}
            {sidePanel === 'node_editor' && selectedNode && (
              <NodeEditorPanel
                node={selectedNode}
                templates={templates}
                onClose={() => { setSidePanel(null); setSelectedNodeId(null); }}
                onUpdate={(patch) => updateNodeData(selectedNode.id, patch)}
                onDelete={() => deleteNode(selectedNode.id)}
                onSelectTrigger={configureTrigger}
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   Side panels
   ═══════════════════════════════════════════════════════════ */

function TriggerPickerPanel({ onClose, onSelectTrigger }) {
  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">Select a trigger</h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
      </div>
      <div className="p-4 space-y-4">
        <div>
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2"><ShoppingCart className="w-3.5 h-3.5" /> Shopify</div>
          <div className="space-y-1">
            {SHOPIFY_EVENTS.map(ev => (
              <button
                key={ev.id}
                className="w-full text-left px-3 py-2.5 text-sm rounded-lg hover:bg-emerald-50 hover:text-emerald-700 transition-colors flex items-center gap-2"
                onClick={() => onSelectTrigger('shopify', ev.id, ev.label)}
              >
                <ShoppingCart className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                <span>{ev.label}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="border-t pt-4">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2"><MessageSquare className="w-3.5 h-3.5" /> WhatsApp</div>
          <div className="space-y-1">
            {WHATSAPP_EVENTS.map(ev => (
              <button
                key={ev.id}
                className="w-full text-left px-3 py-2.5 text-sm rounded-lg hover:bg-green-50 hover:text-green-700 transition-colors flex items-center gap-2"
                onClick={() => onSelectTrigger('whatsapp', ev.id, ev.label)}
              >
                <MessageSquare className="w-4 h-4 text-green-500 flex-shrink-0" />
                <span>{ev.label}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="border-t pt-4">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2"><ScanLine className="w-3.5 h-3.5" /> Delivery</div>
          <button
            className="w-full text-left px-3 py-2.5 text-sm rounded-lg hover:bg-sky-50 hover:text-sky-700 transition-colors flex items-center gap-2"
            onClick={() => onSelectTrigger('delivery', 'status_change', 'Delivery Status Change')}
          >
            <ScanLine className="w-4 h-4 text-sky-500 flex-shrink-0" />
            <span>Status Change</span>
          </button>
        </div>
      </div>
    </>
  );
}

function StepPickerPanel({ onClose, onAddStep }) {
  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">Add a step</h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
      </div>
      <div className="p-4 space-y-3">
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1">Conditions</div>
        <button
          className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-amber-300 hover:bg-amber-50 transition-all flex items-center gap-3 group"
          onClick={() => onAddStep('condition')}
        >
          <div className="p-2 rounded-lg bg-amber-50 text-amber-600 group-hover:bg-amber-100"><SplitSquareHorizontal className="w-5 h-5" /></div>
          <div>
            <div className="text-sm font-semibold text-slate-700">Condition</div>
            <div className="text-xs text-slate-400">Check a value before continuing</div>
          </div>
        </button>

        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 mt-4">Actions</div>
        {ACTION_CATALOG.map(a => (
          <button
            key={a.id}
            className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-all flex items-center gap-3 group"
            onClick={() => onAddStep('action', { type: a.type })}
          >
            <div className="p-2 rounded-lg bg-blue-50 text-blue-600 group-hover:bg-blue-100">{a.icon}</div>
            <div>
              <div className="text-sm font-semibold text-slate-700">{a.label}</div>
            </div>
          </button>
        ))}

        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 mt-4">Timing</div>
        <button
          className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-violet-300 hover:bg-violet-50 transition-all flex items-center gap-3 group"
          onClick={() => onAddStep('delay')}
        >
          <div className="p-2 rounded-lg bg-violet-50 text-violet-600 group-hover:bg-violet-100"><Timer className="w-5 h-5" /></div>
          <div>
            <div className="text-sm font-semibold text-slate-700">Delay</div>
            <div className="text-xs text-slate-400">Wait before the next step</div>
          </div>
        </button>
      </div>
    </>
  );
}

function NodeEditorPanel({ node, templates, onClose, onUpdate, onDelete, onSelectTrigger }) {
  const d = node.data || {};
  const t = node.type;

  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">
          {t === 'startTrigger' ? 'Edit Trigger' : t === 'conditionFlow' ? 'Edit Condition' : t === 'delayFlow' ? 'Edit Delay' : 'Edit Action'}
        </h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
      </div>
      <div className="p-4 space-y-4 flex-1 overflow-y-auto">
        {t === 'startTrigger' && (
          <>
            <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-sm">
              <div className="font-semibold text-emerald-800 mb-1">Current trigger</div>
              <div className="text-emerald-600">{d.source}: {d.event || d.label}</div>
            </div>
            <button
              className="w-full px-4 py-2.5 rounded-lg border border-slate-200 text-sm hover:bg-slate-50 transition-colors"
              onClick={() => onSelectTrigger && onSelectTrigger(d.source, d.event, d.label)} // Re-open trigger picker
            >
              Change trigger…
            </button>
          </>
        )}

        {t === 'conditionFlow' && (
          <>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Variable to check</label>
              <input
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-200 focus:border-blue-400 outline-none"
                value={d.field || ''}
                onChange={(e) => {
                  const f = e.target.value;
                  onUpdate({ field: f, expression: `${f} ${d.operator || '=='} ${d.value || ''}` });
                }}
                placeholder="e.g. total_price, customer.phone"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">Operator</label>
                <select
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={d.operator || '=='}
                  onChange={(e) => {
                    const op = e.target.value;
                    onUpdate({ operator: op, expression: `${d.field || ''} ${op} ${d.value || ''}` });
                  }}
                >
                  <option value="==">equals</option>
                  <option value="!=">not equals</option>
                  <option value=">">greater than</option>
                  <option value=">=">greater or equal</option>
                  <option value="<">less than</option>
                  <option value="<=">less or equal</option>
                  <option value="contains">contains</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">Value</label>
                <input
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={d.value || ''}
                  onChange={(e) => {
                    const v = e.target.value;
                    onUpdate({ value: v, expression: `${d.field || ''} ${d.operator || '=='} ${v}` });
                  }}
                  placeholder="e.g. 150"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">True label</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.trueLabel || ''} onChange={(e) => onUpdate({ trueLabel: e.target.value })} />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">False label</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.falseLabel || ''} onChange={(e) => onUpdate({ falseLabel: e.target.value })} />
              </div>
            </div>
            {d.expression && (
              <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-700">
                <span className="font-semibold">Plain English:</span> Check if <span className="font-mono">{d.field}</span> {d.operator} <span className="font-mono">{d.value}</span>
              </div>
            )}
          </>
        )}

        {t === 'actionFlow' && (
          <>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Action type</label>
              <select
                className="w-full border rounded-lg px-3 py-2 text-sm"
                value={d.actionType || 'send_whatsapp_text'}
                onChange={(e) => {
                  const at = e.target.value;
                  const cat = ACTION_CATALOG.find(a => a.type === at) || ACTION_CATALOG[0];
                  onUpdate({ actionType: at, actionLabel: cat.label });
                }}
              >
                {ACTION_CATALOG.map(a => (
                  <option key={a.id} value={a.type}>{a.label}</option>
                ))}
              </select>
            </div>

            {(d.actionType === 'send_whatsapp_text') && (
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">Message text</label>
                <textarea
                  className="w-full border rounded-lg px-3 py-2 text-sm h-28 resize-none"
                  value={d.text || ''}
                  onChange={(e) => onUpdate({ text: e.target.value, description: e.target.value.slice(0, 50) + (e.target.value.length > 50 ? '…' : '') })}
                  placeholder="Type your message… Use {{ variable }} for dynamic values"
                />
                <div className="text-[10px] text-slate-400 mt-1">Variables: {'{{ phone }}'}, {'{{ order_number }}'}, {'{{ total_price }}'}, {'{{ customer.first_name }}'}</div>
              </div>
            )}

            {(d.actionType === 'send_whatsapp_template') && (
              <>
                <div>
                  <label className="text-xs font-semibold text-slate-500 mb-1 block">Template name</label>
                  <select
                    className="w-full border rounded-lg px-3 py-2 text-sm"
                    value={d.templateName || ''}
                    onChange={(e) => onUpdate({ templateName: e.target.value, description: `Template: ${e.target.value}` })}
                  >
                    <option value="">Select a template…</option>
                    {(templates || []).filter(t => String(t.status || '').toLowerCase() === 'approved').map(t => (
                      <option key={t.name} value={t.name}>{t.name} ({t.language})</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-500 mb-1 block">Language</label>
                  <input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.templateLanguage || 'en'} onChange={(e) => onUpdate({ templateLanguage: e.target.value })} />
                </div>
              </>
            )}

            {(d.actionType === 'shopify_tag') && (
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">Tag to add</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.tag || ''} onChange={(e) => onUpdate({ tag: e.target.value, description: `Tag: ${e.target.value}` })} placeholder="e.g. VIP" />
              </div>
            )}
          </>
        )}

        {t === 'delayFlow' && (
          <div>
            <label className="text-xs font-semibold text-slate-500 mb-1 block">Wait (minutes)</label>
            <input
              type="number"
              className="w-full border rounded-lg px-3 py-2 text-sm"
              value={d.minutes || 10}
              min={1}
              onChange={(e) => onUpdate({ minutes: Math.max(1, Number(e.target.value) || 1) })}
            />
          </div>
        )}
      </div>

      {/* Delete button */}
      {t !== 'startTrigger' && (
        <div className="p-4 border-t">
          <button
            className="w-full px-4 py-2.5 rounded-lg text-sm font-medium text-rose-600 border border-rose-200 hover:bg-rose-50 transition-colors flex items-center justify-center gap-2"
            onClick={onDelete}
          >
            <Trash2 className="w-4 h-4" /> Delete this step
          </button>
        </div>
      )}
    </>
  );
}

/* ═══════════════════════════════════════════════════════════
   Root FlowBuilder — manages list vs canvas view
   ═══════════════════════════════════════════════════════════ */
export default function FlowBuilder() {
  const [view, setView] = useState('list'); // list | canvas
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingFlow, setEditingFlow] = useState(null); // the flow graph being edited
  const [templates, setTemplates] = useState([]);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/automation/rules');
      setRules(Array.isArray(res?.data) ? res.data : []);
    } catch {
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTemplates = useCallback(async () => {
    try {
      const res = await api.get('/admin/whatsapp/templates');
      setTemplates(Array.isArray(res?.data?.templates) ? res.data.templates : []);
    } catch {
      setTemplates([]);
    }
  }, []);

  useEffect(() => {
    loadRules();
    loadTemplates();
  }, [loadRules, loadTemplates]);

  /* ── Build a blank flow (empty canvas) ──────────────── */
  const newBlankFlow = useCallback(() => {
    const trigId = uid();
    // eslint-disable-next-line no-unused-vars
    const addId = uid();
    return {
      nodes: [
        rfNode(trigId, 'startTrigger', 0, 0, { configured: false }),
      ],
      edges: [],
      meta: { name: '', enabled: false },
    };
  }, []);

  /* ── Open an existing rule as a flow graph ────────────── */
  const openRuleAsFlow = useCallback((rule) => {
    // If the rule was saved from FlowBuilder, it has meta.flow_graph
    const saved = rule?.meta?.flow_graph;
    if (saved && saved.nodes && saved.edges) {
      return {
        nodes: saved.nodes,
        edges: saved.edges,
        meta: { name: rule.name || '', enabled: !!rule.enabled, ruleId: rule.id },
      };
    }
    // Otherwise, reconstruct a simple trigger → action graph from the rule
    const trigId = uid();
    // eslint-disable-next-line no-unused-vars
    const actionId = uid();
    // eslint-disable-next-line no-unused-vars
    const addId = uid();
    const source = rule?.trigger?.source || 'whatsapp';
    const event = rule?.trigger?.event || 'message';
    const evLabel = SHOPIFY_EVENTS.find(e => e.id === event)?.label || WHATSAPP_EVENTS.find(e => e.id === event)?.label || event;

    const nodes = [
      rfNode(trigId, 'startTrigger', 0, 0, { configured: true, source, event, label: evLabel, description: `${source}: ${event}` }),
    ];
    const edges = [];

    // Add action nodes
    const acts = Array.isArray(rule.actions) ? rule.actions : [];
    let lastId = trigId;
    let yPos = 200;
    for (const a of acts) {
      const aId = uid();
      const at = String(a.type || '').toLowerCase();
      let actionType = 'send_whatsapp_text';
      let label = 'Send Text';
      if (at.includes('template')) { actionType = 'send_whatsapp_template'; label = 'Send Template'; }
      else if (at === 'exit') { actionType = 'exit'; label = 'Stop'; }
      else if (at.includes('tag')) { actionType = 'shopify_tag'; label = 'Tag Customer'; }
      else if (at === 'delay') { actionType = 'delay'; label = 'Delay'; }

      if (at === 'delay') {
        nodes.push(rfNode(aId, 'delayFlow', 0, yPos, { minutes: a.minutes || 10 }));
      } else {
        nodes.push(rfNode(aId, 'actionFlow', 0, yPos, {
          actionType, actionLabel: label,
          text: a.text || '',
          templateName: a.template_name || '',
          templateLanguage: a.language || 'en',
          tag: a.tag || '',
          description: a.preview || a.text?.slice(0, 50) || a.template_name || '',
        }));
      }
      edges.push(rfEdge(lastId, aId));
      lastId = aId;
      yPos += 200;
    }

    // Add final addStep
    const finalAdd = uid();
    nodes.push(rfNode(finalAdd, 'addStep', 0, yPos, {}));
    edges.push(rfEdge(lastId, finalAdd));

    return {
      nodes, edges,
      meta: { name: rule.name || '', enabled: !!rule.enabled, ruleId: rule.id },
    };
  }, []);

  /* ── Save flow to backend ───────────────────────────── */
  const saveToBackend = useCallback(async (rule, existingId) => {
    const isUpdate = !!existingId;
    if (isUpdate) {
      const next = rules.map(r => r.id === existingId ? rule : r);
      await api.post('/automation/rules', { rules: next });
      setRules(next);
    } else {
      const next = [...rules, rule];
      await api.post('/automation/rules', { rules: next });
      setRules(next);
    }
    // Reload
    try {
      const res = await api.get('/automation/rules');
      setRules(Array.isArray(res?.data) ? res.data : []);
    } catch {}
  }, [rules]);

  /* ── Handlers ───────────────────────────────────────── */
  const handleSelectFlow = useCallback((rule, template) => {
    if (template) {
      const flow = template.build();
      setEditingFlow(flow);
      setView('canvas');
    } else if (rule) {
      const flow = openRuleAsFlow(rule);
      setEditingFlow(flow);
      setView('canvas');
    }
  }, [openRuleAsFlow]);

  const handleNewFlow = useCallback(() => {
    setEditingFlow(newBlankFlow());
    setView('canvas');
  }, [newBlankFlow]);

  const handleDeleteFlow = useCallback(async (id) => {
    if (!window.confirm('Delete this flow?')) return;
    const next = rules.filter(r => r.id !== id);
    try {
      await api.post('/automation/rules', { rules: next });
      setRules(next);
    } catch {}
  }, [rules]);

  const handleBack = useCallback(() => {
    setView('list');
    setEditingFlow(null);
    loadRules();
  }, [loadRules]);

  if (view === 'canvas' && editingFlow) {
    return (
      <ReactFlowProvider>
        <FlowBuilderCanvas
          initialFlow={editingFlow}
          templates={templates}
          allRules={rules}
          onBack={handleBack}
          onSaveToBackend={saveToBackend}
        />
      </ReactFlowProvider>
    );
  }

  return (
    <FlowsListView
      flows={rules}
      loading={loading}
      onSelect={handleSelectFlow}
      onNewFlow={handleNewFlow}
      onDelete={handleDeleteFlow}
    />
  );
}
