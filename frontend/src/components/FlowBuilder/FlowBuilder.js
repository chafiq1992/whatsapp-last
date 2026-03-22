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
import EmojiPicker from 'emoji-picker-react';

/* ═══════════════════════════════════════════════════════════
   Rich Trigger / Action / Condition catalogs
   Real variables from Shopify, WhatsApp, and Delivery APIs
   ═══════════════════════════════════════════════════════════ */
const SHOPIFY_EVENTS = [
  // ── Orders ──
  { id: 'orders/paid', label: 'Order Paid', cat: 'Orders', variables: [
    { key: 'order_number', label: 'Order Number' }, { key: 'id', label: 'Order ID' },
    { key: 'total_price', label: 'Total Price', type: 'number' }, { key: 'subtotal_price', label: 'Subtotal', type: 'number' },
    { key: 'total_discounts', label: 'Total Discounts', type: 'number' }, { key: 'total_tax', label: 'Total Tax', type: 'number' },
    { key: 'currency', label: 'Currency' }, { key: 'financial_status', label: 'Financial Status' },
    { key: 'fulfillment_status', label: 'Fulfillment Status' }, { key: 'tags', label: 'Order Tags' },
    { key: 'note', label: 'Order Note' }, { key: 'created_at', label: 'Created At' }, { key: 'note_attributes', label: 'Note Attributes' },
    { key: 'customer.phone', label: 'Customer Phone' }, { key: 'customer.first_name', label: 'Customer First Name' },
    { key: 'customer.last_name', label: 'Customer Last Name' }, { key: 'customer.email', label: 'Customer Email' },
    { key: 'customer.orders_count', label: 'Customer Order Count', type: 'number' },
    { key: 'customer.total_spent', label: 'Customer Total Spent', type: 'number' },
    { key: 'customer.tags', label: 'Customer Tags' },
    { key: 'shipping_address.city', label: 'Shipping City' }, { key: 'shipping_address.province', label: 'Shipping Province' },
    { key: 'shipping_address.country', label: 'Shipping Country' }, { key: 'shipping_address.zip', label: 'Shipping ZIP' },
    { key: 'shipping_address.address1', label: 'Shipping Address' }, { key: 'shipping_address.phone', label: 'Shipping Phone' },
    { key: 'billing_address.city', label: 'Billing City' },
    { key: 'line_items[].title', label: 'Product Titles' }, { key: 'line_items[].quantity', label: 'Item Quantities', type: 'number' },
    { key: 'line_items[].price', label: 'Item Prices', type: 'number' }, { key: 'line_items[].sku', label: 'Item SKU' },
    { key: 'line_items[].grams', label: 'Item Weight (g)', type: 'number' }, { key: 'line_items[].vendor', label: 'Item Vendor' },
    { key: 'discount_codes[].code', label: 'Discount Codes' }, { key: 'discount_applications', label: 'Discount Applications' },
    { key: 'payment_gateway_names', label: 'Payment Method' },
    { key: 'source_name', label: 'Order Source' }, { key: 'landing_site', label: 'Landing Page' },
    { key: 'referring_site', label: 'Referring Site' },
  ]},
  { id: 'orders/create', label: 'New Order Created', cat: 'Orders', variables: 'SAME_AS:orders/paid' },
  { id: 'orders/updated', label: 'Order Updated', cat: 'Orders', variables: 'SAME_AS:orders/paid' },
  { id: 'orders/cancelled', label: 'Order Cancelled', cat: 'Orders', variables: 'SAME_AS:orders/paid' },
  { id: 'orders/fulfilled', label: 'Order Fulfilled', cat: 'Orders', variables: 'SAME_AS:orders/paid' },
  { id: 'orders/partially_fulfilled', label: 'Order Partially Fulfilled', cat: 'Orders', variables: 'SAME_AS:orders/paid' },
  { id: 'refunds/create', label: 'Refund Created', cat: 'Orders', variables: 'SAME_AS:orders/paid' },
  // ── Fulfillments ──
  { id: 'fulfillments/create', label: 'Fulfillment Created', cat: 'Fulfillments', variables: [
    { key: 'tracking_number', label: 'Tracking Number' }, { key: 'tracking_url', label: 'Tracking URL' },
    { key: 'tracking_company', label: 'Shipping Carrier' }, { key: 'status', label: 'Fulfillment Status' },
    { key: 'order_id', label: 'Order ID' }, { key: 'order.order_number', label: 'Order Number' },
    { key: 'customer.phone', label: 'Customer Phone' }, { key: 'customer.first_name', label: 'First Name' },
    { key: 'customer.last_name', label: 'Last Name' }, { key: 'customer.email', label: 'Email' },
    { key: 'destination.city', label: 'Destination City' }, { key: 'destination.country', label: 'Destination Country' },
    { key: 'line_items[].title', label: 'Fulfilled Items' }, { key: 'line_items[].quantity', label: 'Fulfilled Qty', type: 'number' },
  ]},
  { id: 'fulfillments/update', label: 'Fulfillment Updated', cat: 'Fulfillments', variables: 'SAME_AS:fulfillments/create' },
  // ── Customers ──
  { id: 'customers/create', label: 'New Customer', cat: 'Customers', variables: [
    { key: 'id', label: 'Customer ID' }, { key: 'first_name', label: 'First Name' }, { key: 'last_name', label: 'Last Name' },
    { key: 'email', label: 'Email' }, { key: 'phone', label: 'Phone' },
    { key: 'orders_count', label: 'Orders Count', type: 'number' }, { key: 'total_spent', label: 'Total Spent', type: 'number' },
    { key: 'tags', label: 'Customer Tags' }, { key: 'verified_email', label: 'Email Verified', type: 'boolean' },
    { key: 'accepts_marketing', label: 'Accepts Marketing', type: 'boolean' },
    { key: 'default_address.city', label: 'City' }, { key: 'default_address.province', label: 'Province' },
    { key: 'default_address.country', label: 'Country' }, { key: 'default_address.zip', label: 'ZIP Code' },
    { key: 'created_at', label: 'Created At' }, { key: 'note', label: 'Customer Note' },
  ]},
  { id: 'customers/update', label: 'Customer Updated', cat: 'Customers', variables: 'SAME_AS:customers/create' },
  // ── Checkouts ──
  { id: 'checkouts/update', label: 'Abandoned Checkout', cat: 'Checkouts', variables: [
    { key: 'id', label: 'Checkout ID' }, { key: 'token', label: 'Checkout Token' },
    { key: 'abandoned_checkout_url', label: 'Recovery URL' },
    { key: 'total_price', label: 'Total Price', type: 'number' }, { key: 'subtotal_price', label: 'Subtotal', type: 'number' },
    { key: 'total_discounts', label: 'Total Discounts', type: 'number' },
    { key: 'email', label: 'Email' }, { key: 'phone', label: 'Phone' },
    { key: 'customer.first_name', label: 'First Name' }, { key: 'customer.last_name', label: 'Last Name' },
    { key: 'line_items[].title', label: 'Cart Items' }, { key: 'line_items[].quantity', label: 'Item Qty', type: 'number' },
    { key: 'line_items[].price', label: 'Item Price', type: 'number' },
    { key: 'shipping_address.city', label: 'Shipping City' }, { key: 'currency', label: 'Currency' },
  ]},
  // ── Draft Orders ──
  { id: 'draft_orders/create', label: 'Draft Order Created', cat: 'Draft Orders', variables: [
    { key: 'id', label: 'Draft ID' }, { key: 'name', label: 'Draft Name' },
    { key: 'invoice_url', label: 'Invoice URL' }, { key: 'status', label: 'Status' },
    { key: 'total_price', label: 'Total Price', type: 'number' },
    { key: 'customer.phone', label: 'Customer Phone' }, { key: 'customer.first_name', label: 'First Name' },
    { key: 'customer.email', label: 'Email' }, { key: 'note', label: 'Note' },
  ]},
  { id: 'draft_orders/update', label: 'Draft Order Updated', cat: 'Draft Orders', variables: 'SAME_AS:draft_orders/create' },
  // ── Products ──
  { id: 'products/create', label: 'Product Created', cat: 'Products', variables: [
    { key: 'id', label: 'Product ID' }, { key: 'title', label: 'Product Title' },
    { key: 'vendor', label: 'Vendor' }, { key: 'product_type', label: 'Product Type' },
    { key: 'tags', label: 'Product Tags' }, { key: 'status', label: 'Status' },
    { key: 'variants[].price', label: 'Variant Price', type: 'number' },
    { key: 'variants[].inventory_quantity', label: 'Inventory Qty', type: 'number' },
    { key: 'variants[].sku', label: 'Variant SKU' }, { key: 'variants[].title', label: 'Variant Title' },
  ]},
  { id: 'products/update', label: 'Product Updated', cat: 'Products', variables: 'SAME_AS:products/create' },
  { id: 'inventory_levels/update', label: 'Inventory Changed', cat: 'Products', variables: [
    { key: 'inventory_item_id', label: 'Item ID' }, { key: 'available', label: 'Available Qty', type: 'number' },
    { key: 'location_id', label: 'Location ID' },
  ]},
];

// Resolve "SAME_AS" references
SHOPIFY_EVENTS.forEach(ev => {
  if (typeof ev.variables === 'string' && ev.variables.startsWith('SAME_AS:')) {
    const ref = ev.variables.replace('SAME_AS:', '');
    const src = SHOPIFY_EVENTS.find(e => e.id === ref);
    ev.variables = src ? src.variables : [];
  }
});

const WHATSAPP_EVENTS = [
  { id: 'message', label: 'Incoming Message', cat: 'Messages', mode: 'incoming', variables: [
    { key: 'phone', label: 'Sender Phone' }, { key: 'message_text', label: 'Message Text' },
    { key: 'message_type', label: 'Message Type' }, { key: 'contact_name', label: 'Contact Name' },
    { key: 'timestamp', label: 'Timestamp' }, { key: 'is_group', label: 'Is Group Chat', type: 'boolean' },
  ]},
  { id: 'no_reply', label: 'No Agent Reply', cat: 'Messages', mode: 'no_reply', variables: [
    { key: 'phone', label: 'Customer Phone' }, { key: 'contact_name', label: 'Contact Name' },
    { key: 'minutes_waiting', label: 'Minutes Waiting', type: 'number' },
    { key: 'last_message_text', label: 'Last Message' }, { key: 'conversation_status', label: 'Conv. Status' },
  ]},
  { id: 'interactive', label: 'Button Clicked', cat: 'Interactive', mode: 'button', variables: [
    { key: 'phone', label: 'Customer Phone' }, { key: 'button_title', label: 'Button Title' },
    { key: 'button_id', label: 'Button ID' }, { key: 'contact_name', label: 'Contact Name' },
    { key: 'list_title', label: 'List Selection Title' }, { key: 'list_id', label: 'List Selection ID' },
  ]},
  { id: 'first_message', label: 'First-Time Message', cat: 'Messages', mode: 'incoming', variables: [
    { key: 'phone', label: 'Sender Phone' }, { key: 'message_text', label: 'Message Text' },
    { key: 'contact_name', label: 'Contact Name' },
  ]},
  { id: 'keyword_match', label: 'Keyword Match', cat: 'Messages', mode: 'incoming', variables: [
    { key: 'phone', label: 'Sender Phone' }, { key: 'message_text', label: 'Message Text' },
    { key: 'matched_keyword', label: 'Matched Keyword' }, { key: 'contact_name', label: 'Contact Name' },
  ]},
  { id: 'media_received', label: 'Media Received', cat: 'Messages', mode: 'incoming', variables: [
    { key: 'phone', label: 'Sender Phone' }, { key: 'media_type', label: 'Media Type' },
    { key: 'media_url', label: 'Media URL' }, { key: 'caption', label: 'Caption' },
    { key: 'contact_name', label: 'Contact Name' },
  ]},
];

const DELIVERY_EVENTS = [
  { id: 'status_change', label: 'Delivery Status Change', cat: 'Status', variables: [
    { key: 'order_id', label: 'Order ID' }, { key: 'tracking_number', label: 'Tracking Number' }, { key: 'tracking_url', label: 'Tracking URL' },
    { key: 'status', label: 'Delivery Status' }, { key: 'previous_status', label: 'Previous Status' },
    { key: 'customer_phone', label: 'Customer Phone' }, { key: 'customer_name', label: 'Customer Name' },
    { key: 'city', label: 'Delivery City' }, { key: 'address', label: 'Delivery Address' }, { key: 'shipping_zone', label: 'Shipping Zone' },
    { key: 'driver_name', label: 'Driver Name' }, { key: 'driver_phone', label: 'Driver Phone' },
    { key: 'estimated_delivery', label: 'Estimated Delivery' }, { key: 'total_price', label: 'Order Total', type: 'number' },
    { key: 'cod_amount', label: 'COD Amount', type: 'number' }, { key: 'delivery_fee', label: 'Delivery Fee', type: 'number' },
    { key: 'attempt_count', label: 'Attempt Count', type: 'number' }, { key: 'notes', label: 'Delivery Notes' },
    { key: 'warehouse', label: 'Warehouse / Hub' }, { key: 'delivery_company', label: 'Delivery Company' },
  ]},
  { id: 'out_for_delivery', label: 'Out for Delivery', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
  { id: 'delivered', label: 'Delivered', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
  { id: 'failed_delivery', label: 'Failed Delivery', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
  { id: 'returned', label: 'Returned to Sender', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
  { id: 'pickup_ready', label: 'Ready for Pickup', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
  { id: 'driver_assigned', label: 'Driver Assigned', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
  { id: 'cod_collected', label: 'COD Collected', cat: 'Status', variables: 'SAME_AS_DEL:status_change' },
];

DELIVERY_EVENTS.forEach(ev => {
  if (typeof ev.variables === 'string' && ev.variables.startsWith('SAME_AS_DEL:')) {
    const ref = ev.variables.replace('SAME_AS_DEL:', '');
    const src = DELIVERY_EVENTS.find(e => e.id === ref);
    ev.variables = src ? src.variables : [];
  }
});

const ALL_SHOPIFY_VARS = Array.from(new Map(SHOPIFY_EVENTS.flatMap(e => Array.isArray(e.variables) ? e.variables : []).map(v => [v.key, v])).values());
const ALL_DELIVERY_VARS = Array.from(new Map(DELIVERY_EVENTS.flatMap(e => Array.isArray(e.variables) ? e.variables : []).map(v => [v.key, v])).values());
const ALL_WHATSAPP_VARS = Array.from(new Map(WHATSAPP_EVENTS.flatMap(e => Array.isArray(e.variables) ? e.variables : []).map(v => [v.key, v])).values());


/* Helper: get variables for the active trigger */
function getVariablesForTrigger(source, event) {
  const all = source === 'shopify' ? SHOPIFY_EVENTS : source === 'whatsapp' ? WHATSAPP_EVENTS : DELIVERY_EVENTS;
  const ev = all.find(e => e.id === event);
  const vars = Array.isArray(ev?.variables) ? ev.variables : [];
  return [...vars, { key: '__custom__', label: '✏️ Custom variable…' }];
}

const ACTION_CATALOG = [
  { id: 'send_text',         label: 'Send Text Message',       icon: <MessageSquare className="w-4 h-4 text-blue-500" />,   type: 'send_whatsapp_text',     desc: 'Send a plain WhatsApp text with variables' },
  { id: 'send_template',     label: 'Send WhatsApp Template',  icon: <MessageSquare className="w-4 h-4 text-emerald-500" />, type: 'send_whatsapp_template', desc: 'Send an approved template message' },
  { id: 'send_buttons',      label: 'Send Button Message',     icon: <MessageSquare className="w-4 h-4 text-indigo-500" />,  type: 'send_buttons',           desc: 'Interactive message with reply buttons' },
  { id: 'send_image',        label: 'Send Image',              icon: <MessageSquare className="w-4 h-4 text-pink-500" />,    type: 'send_image',             desc: 'Send an image with optional caption' },
  { id: 'send_audio',        label: 'Send Audio',              icon: <MessageSquare className="w-4 h-4 text-violet-500" />,  type: 'send_audio',             desc: 'Send a voice message or audio file' },
  { id: 'tag_customer',      label: 'Tag Customer (Shopify)',   icon: <Zap className="w-4 h-4 text-amber-500" />,            type: 'shopify_tag',            desc: 'Add a tag to the Shopify customer' },
  { id: 'remove_tag',        label: 'Remove Tag (Shopify)',     icon: <Zap className="w-4 h-4 text-orange-500" />,           type: 'shopify_remove_tag',     desc: 'Remove a tag from the Shopify customer' },
  { id: 'assign_agent',      label: 'Assign to Agent',         icon: <Zap className="w-4 h-4 text-cyan-500" />,             type: 'assign_agent',           desc: 'Route conversation to a specific agent' },
  { id: 'close_conversation',label: 'Close Conversation',      icon: <Ban className="w-4 h-4 text-slate-500" />,            type: 'close_conversation',     desc: 'Mark conversation as resolved' },
  { id: 'exit',              label: 'Stop / Exit',              icon: <Ban className="w-4 h-4 text-rose-500" />,             type: 'exit',                   desc: 'End the workflow here' },
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
  const currentTriggerNode = useMemo(() => nodes.find(n => n.type === 'startTrigger' && n.data?.configured), [nodes]);

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
                triggerSource={currentTriggerNode?.data.source}
                triggerEvent={currentTriggerNode?.data.event}
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
  const [search, setSearch] = React.useState('');
  const lc = search.toLowerCase();
  const filterEv = (ev) => !lc || ev.label.toLowerCase().includes(lc) || ev.id.toLowerCase().includes(lc);
  const shopifyCats = {};
  SHOPIFY_EVENTS.filter(filterEv).forEach(ev => { const c = ev.cat || 'Other'; if (!shopifyCats[c]) shopifyCats[c] = []; shopifyCats[c].push(ev); });
  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">Select a trigger</h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
      </div>
      <div className="px-4 pt-3 pb-1">
        <input className="w-full border rounded-lg px-3 py-2 text-sm placeholder-slate-400 focus:ring-2 focus:ring-blue-200 outline-none" placeholder="Search triggers…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <div className="p-4 space-y-4 overflow-y-auto flex-1">
        <div>
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2"><ShoppingCart className="w-3.5 h-3.5" /> Shopify</div>
          {Object.entries(shopifyCats).map(([cat, evts]) => (
            <div key={cat} className="mb-3">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1 pl-1">{cat}</div>
              <div className="space-y-0.5">{evts.map(ev => (
                <button key={ev.id} className="w-full text-left px-3 py-2 text-sm rounded-lg hover:bg-emerald-50 hover:text-emerald-700 transition-colors flex items-center gap-2" onClick={() => onSelectTrigger('shopify', ev.id, ev.label)}>
                  <ShoppingCart className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0" /><span className="truncate">{ev.label}</span>
                  <span className="text-[9px] text-slate-300 ml-auto flex-shrink-0">{Array.isArray(ev.variables) ? ev.variables.length : 0} vars</span>
                </button>))}</div>
            </div>))}
        </div>
        <div className="border-t pt-4">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2"><MessageSquare className="w-3.5 h-3.5" /> WhatsApp</div>
          <div className="space-y-0.5">{WHATSAPP_EVENTS.filter(filterEv).map(ev => (
            <button key={ev.id} className="w-full text-left px-3 py-2 text-sm rounded-lg hover:bg-green-50 hover:text-green-700 transition-colors flex items-center gap-2" onClick={() => onSelectTrigger('whatsapp', ev.id, ev.label)}>
              <MessageSquare className="w-3.5 h-3.5 text-green-500 flex-shrink-0" /><span>{ev.label}</span>
              <span className="text-[9px] text-slate-300 ml-auto flex-shrink-0">{Array.isArray(ev.variables) ? ev.variables.length : 0} vars</span>
            </button>))}</div>
        </div>
        <div className="border-t pt-4">
          <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2"><ScanLine className="w-3.5 h-3.5" /> Delivery</div>
          <div className="space-y-0.5">{DELIVERY_EVENTS.filter(filterEv).map(ev => (
            <button key={ev.id} className="w-full text-left px-3 py-2 text-sm rounded-lg hover:bg-sky-50 hover:text-sky-700 transition-colors flex items-center gap-2" onClick={() => onSelectTrigger('delivery', ev.id, ev.label)}>
              <ScanLine className="w-3.5 h-3.5 text-sky-500 flex-shrink-0" /><span>{ev.label}</span>
              <span className="text-[9px] text-slate-300 ml-auto flex-shrink-0">{Array.isArray(ev.variables) ? ev.variables.length : 0} vars</span>
            </button>))}</div>
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
      <div className="p-4 space-y-3 overflow-y-auto flex-1">
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1">Conditions</div>
        <button className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-amber-300 hover:bg-amber-50 transition-all flex items-center gap-3 group" onClick={() => onAddStep('condition')}>
          <div className="p-2 rounded-lg bg-amber-50 text-amber-600 group-hover:bg-amber-100"><SplitSquareHorizontal className="w-5 h-5" /></div>
          <div><div className="text-sm font-semibold text-slate-700">Condition</div><div className="text-xs text-slate-400">Check a value before continuing</div></div>
        </button>
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 mt-4">Actions</div>
        {ACTION_CATALOG.map(a => (
          <button key={a.id} className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-blue-300 hover:bg-blue-50 transition-all flex items-center gap-3 group" onClick={() => onAddStep('action', { type: a.type })}>
            <div className="p-2 rounded-lg bg-blue-50 text-blue-600 group-hover:bg-blue-100">{a.icon}</div>
            <div className="min-w-0"><div className="text-sm font-semibold text-slate-700">{a.label}</div>{a.desc && <div className="text-xs text-slate-400 truncate">{a.desc}</div>}</div>
          </button>
        ))}
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 mt-4">Timing</div>
        <button className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-violet-300 hover:bg-violet-50 transition-all flex items-center gap-3 group" onClick={() => onAddStep('delay')}>
          <div className="p-2 rounded-lg bg-violet-50 text-violet-600 group-hover:bg-violet-100"><Timer className="w-5 h-5" /></div>
          <div><div className="text-sm font-semibold text-slate-700">Delay</div><div className="text-xs text-slate-400">Wait before the next step</div></div>
        </button>
      </div>
    </>
  );
}

function PlatformVariableSelector({ onInsert }) {
  const [activeTab, setActiveTab] = React.useState('shopify');
  const [copied, setCopied] = React.useState(null);

  const handleCopyAndInsert = (v) => {
    const textToInsert = `{{ ${v.key} }}`;
    onInsert(textToInsert);
    try { navigator.clipboard.writeText(textToInsert); } catch (e) {}
    setCopied(v.key);
    setTimeout(() => setCopied(null), 1500);
  };

  const renderVars = (vars) => (
    <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto p-3 bg-slate-50 border-t border-slate-100">
      {vars.filter(v => v.key !== '__custom__').map(v => (
        <button
          key={v.key}
          type="button"
          onClick={() => handleCopyAndInsert(v)}
          className="relative px-2.5 py-1.5 rounded-full text-[10px] font-medium bg-white text-slate-600 border border-slate-200 hover:border-blue-400 hover:text-blue-600 hover:bg-blue-50 transition-all shadow-sm flex items-center gap-1"
          title={`Click to copy and insert {{ ${v.key} }}`}
        >
          {v.label}
          {copied === v.key && (
            <span className="absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-800 text-white text-[10px] px-2 py-0.5 rounded shadow-lg whitespace-nowrap z-10 animate-fade-in">
              Copied & Inserted!
              <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-800" />
            </span>
          )}
        </button>
      ))}
    </div>
  );

  return (
    <div className="mt-3 border border-slate-200 rounded-xl overflow-hidden shadow-sm bg-white">
      <div className="flex border-b bg-slate-50/50">
        <button type="button" onClick={() => setActiveTab('shopify')} className={`flex-1 py-2 text-xs font-semibold flex justify-center items-center gap-1.5 transition-colors ${activeTab==='shopify' ? 'text-blue-600 border-b-2 border-blue-500 bg-white' : 'text-slate-500 hover:text-slate-700'}`}><ShoppingCart className="w-3.5 h-3.5"/> Shopify</button>
        <button type="button" onClick={() => setActiveTab('delivery')} className={`flex-1 py-2 text-xs font-semibold flex justify-center items-center gap-1.5 transition-colors ${activeTab==='delivery' ? 'text-sky-600 border-b-2 border-sky-500 bg-white' : 'text-slate-500 hover:text-slate-700'}`}><ScanLine className="w-3.5 h-3.5"/> Delivery</button>
        <button type="button" onClick={() => setActiveTab('whatsapp')} className={`flex-1 py-2 text-xs font-semibold flex justify-center items-center gap-1.5 transition-colors ${activeTab==='whatsapp' ? 'text-green-600 border-b-2 border-green-500 bg-white' : 'text-slate-500 hover:text-slate-700'}`}><MessageSquare className="w-3.5 h-3.5"/> WhatsApp</button>
      </div>
      {activeTab === 'shopify' && renderVars(ALL_SHOPIFY_VARS)}
      {activeTab === 'delivery' && renderVars(ALL_DELIVERY_VARS)}
      {activeTab === 'whatsapp' && renderVars(ALL_WHATSAPP_VARS)}
    </div>
  );
}

function NodeEditorPanel({ node, templates, onClose, onUpdate, onDelete, onSelectTrigger, triggerSource, triggerEvent }) {
  const d = node.data || {};
  const t = node.type;
  const [customField, setCustomField] = React.useState('');
  const trigVars = React.useMemo(() => getVariablesForTrigger(triggerSource, triggerEvent), [triggerSource, triggerEvent]);
  const insertVar = (v) => { const cur = d.text || ''; onUpdate({ text: cur + v, description: (cur + v).slice(0, 50) }); };

  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">{t === 'startTrigger' ? 'Edit Trigger' : t === 'conditionFlow' ? 'Edit Condition' : t === 'delayFlow' ? 'Edit Delay' : 'Edit Action'}</h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
      </div>
      <div className="p-4 space-y-4 flex-1 overflow-y-auto">
        {t === 'startTrigger' && (<>
          <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-sm">
            <div className="font-semibold text-emerald-800 mb-1">Current trigger</div>
            <div className="text-emerald-600">{d.source}: {d.event || d.label}</div>
          </div>
          <button className="w-full px-4 py-2.5 rounded-lg border border-slate-200 text-sm hover:bg-slate-50" onClick={() => onSelectTrigger && onSelectTrigger(d.source, d.event, d.label)}>Change trigger…</button>
          <div>
            <div className="text-xs font-semibold text-slate-500 mb-1">Available variables ({trigVars.filter(v => v.key !== '__custom__').length}):</div>
            <div className="flex flex-wrap gap-1 max-h-40 overflow-y-auto">
              {trigVars.filter(v => v.key !== '__custom__').map(v => (
                <span key={v.key} className="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-100 font-mono" title={`{{ ${v.key} }}`}>{v.label}</span>
              ))}
            </div>
          </div>
        </>)}

        {t === 'conditionFlow' && (<>
          <div>
            <label className="text-xs font-semibold text-slate-500 mb-1 block">Variable to check</label>
            <select className="w-full border rounded-lg px-3 py-2 text-sm bg-white" value={d.field || ''} onChange={(e) => {
              const f = e.target.value;
              if (f === '__custom__') { setCustomField(''); onUpdate({ field: '' }); return; }
              const vDef = trigVars.find(v => v.key === f);
              onUpdate({ field: f, fieldLabel: vDef?.label || f, expression: `${vDef?.label || f} ${d.operator || '=='} ${d.value || ''}` });
            }}>
              <option value="">— Select a variable —</option>
              {trigVars.map(v => (<option key={v.key} value={v.key}>{v.label}{v.type ? ` (${v.type})` : ''}</option>))}
            </select>
            {(d.field === '__custom__' || customField !== '') && (
              <input className="w-full border rounded-lg px-3 py-2 text-sm mt-2" placeholder="Custom variable key…" value={customField} onChange={(e) => { setCustomField(e.target.value); onUpdate({ field: e.target.value, fieldLabel: e.target.value, expression: `${e.target.value} ${d.operator || '=='} ${d.value || ''}` }); }} />
            )}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Operator</label>
              <select className="w-full border rounded-lg px-3 py-2 text-sm" value={d.operator || '=='} onChange={(e) => onUpdate({ operator: e.target.value, expression: `${d.fieldLabel || d.field || ''} ${e.target.value} ${d.value || ''}` })}>
                <option value="==">equals</option><option value="!=">not equals</option>
                <option value=">">greater than</option><option value=">=">greater or equal</option>
                <option value="<">less than</option><option value="<=">less or equal</option>
                <option value="contains">contains</option><option value="not_contains">does not contain</option>
                <option value="starts_with">starts with</option><option value="ends_with">ends with</option>
                <option value="is_empty">is empty</option><option value="is_not_empty">is not empty</option>
                <option value="matches">regex matches</option>
                <option value="in">is in list (comma separated)</option>
                <option value="not_in">is not in list</option>
                <option value="is_true">is exactly true</option>
                <option value="is_false">is exactly false</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Value</label>
              <input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.value || ''} onChange={(e) => onUpdate({ value: e.target.value, expression: `${d.fieldLabel || d.field || ''} ${d.operator || '=='} ${e.target.value}` })} placeholder="e.g. 150, VIP, Casablanca" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">True label</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.trueLabel || ''} onChange={(e) => onUpdate({ trueLabel: e.target.value })} /></div>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">False label</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.falseLabel || ''} onChange={(e) => onUpdate({ falseLabel: e.target.value })} /></div>
          </div>
          {d.expression && (
            <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-700">
              <span className="font-semibold">Summary:</span> If <span className="font-mono font-semibold">{d.fieldLabel || d.field}</span> {d.operator} <span className="font-mono font-semibold">{d.value}</span>
            </div>
          )}
        </>)}

        {t === 'actionFlow' && (<>
          <div>
            <label className="text-xs font-semibold text-slate-500 mb-1 block">Action type</label>
            <select className="w-full border rounded-lg px-3 py-2 text-sm" value={d.actionType || 'send_whatsapp_text'} onChange={(e) => { const cat = ACTION_CATALOG.find(a => a.type === e.target.value) || ACTION_CATALOG[0]; onUpdate({ actionType: e.target.value, actionLabel: cat.label }); }}>
              {ACTION_CATALOG.map(a => (<option key={a.id} value={a.type}>{a.label}</option>))}
            </select>
          </div>
          {d.actionType === 'send_whatsapp_text' && (
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Message text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-28 resize-none" value={d.text || ''} onChange={(e) => onUpdate({ text: e.target.value, description: e.target.value.slice(0, 50) + (e.target.value.length > 50 ? '…' : '') })} placeholder="Type your message… Click variables below to insert" />
              <div className="flex justify-end mt-1 mb-2">
                <button type="button" className="text-xl opacity-70 hover:opacity-100 transition-opacity" onClick={() => onUpdate({ _showEmoji: !d._showEmoji })}>😀</button>
              </div>
              {d._showEmoji && (
                <div className="mb-3 border rounded-xl overflow-hidden shadow-sm">
                  <EmojiPicker width="100%" height={300} onEmojiClick={(ev) => insertVar(ev.emoji)} />
                </div>
              )}
              <PlatformVariableSelector onInsert={insertVar} />
            </div>
          )}
          {d.actionType === 'send_whatsapp_template' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Template</label>
              <select className="w-full border rounded-lg px-3 py-2 text-sm" value={d.templateName || ''} onChange={(e) => onUpdate({ templateName: e.target.value, description: `Template: ${e.target.value}` })}>
                <option value="">Select a template…</option>
                {(templates || []).filter(tp => String(tp.status || '').toLowerCase() === 'approved').map(tp => (<option key={tp.name} value={tp.name}>{tp.name} ({tp.language})</option>))}
              </select>
            </div>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Language</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.templateLanguage || 'en'} onChange={(e) => onUpdate({ templateLanguage: e.target.value })} /></div>
          </>)}
          {d.actionType === 'send_buttons' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Body text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none" value={d.buttonsText || ''} onChange={(e) => onUpdate({ buttonsText: e.target.value, description: 'Buttons: ' + e.target.value.slice(0, 30) })} placeholder="Message body…" />
              <div className="flex justify-end mt-1 mb-2">
                <button type="button" className="text-xl opacity-70 hover:opacity-100 transition-opacity" onClick={() => onUpdate({ _showEmojiBtn: !d._showEmojiBtn })}>😀</button>
              </div>
              {d._showEmojiBtn && (
                <div className="mb-3 border rounded-xl overflow-hidden shadow-sm">
                  <EmojiPicker width="100%" height={300} onEmojiClick={(ev) => onUpdate({ buttonsText: (d.buttonsText || '') + ev.emoji })} />
                </div>
              )}
              <PlatformVariableSelector onInsert={(v) => onUpdate({ buttonsText: (d.buttonsText || '') + v })} />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Buttons (one per line)</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none font-mono" value={d.buttonsLines || ''} onChange={(e) => onUpdate({ buttonsLines: e.target.value })} placeholder={"Confirm ✅\nChange order\nTalk to agent"} />
            </div>
          </>)}
          {d.actionType === 'send_image' && (<>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Image URL</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.imageUrl || ''} onChange={(e) => onUpdate({ imageUrl: e.target.value, description: 'Image' })} placeholder="https://…" /></div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.caption || ''} onChange={(e) => onUpdate({ caption: e.target.value })} />
              <div className="flex justify-end mt-1 mb-2">
                <button type="button" className="text-xl opacity-70 hover:opacity-100 transition-opacity" onClick={() => onUpdate({ _showEmojiCap: !d._showEmojiCap })}>😀</button>
              </div>
              {d._showEmojiCap && (
                <div className="mb-3 border rounded-xl overflow-hidden shadow-sm">
                  <EmojiPicker width="100%" height={300} onEmojiClick={(ev) => onUpdate({ caption: (d.caption || '') + ev.emoji })} />
                </div>
              )}
              <PlatformVariableSelector onInsert={(v) => onUpdate({ caption: (d.caption || '') + v })} />
            </div>
          </>)}
          {d.actionType === 'send_audio' && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Audio URL</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.audioUrl || ''} onChange={(e) => onUpdate({ audioUrl: e.target.value, description: 'Audio' })} placeholder="https://…" /></div>
          )}
          {(d.actionType === 'shopify_tag' || d.actionType === 'shopify_remove_tag') && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">{d.actionType === 'shopify_remove_tag' ? 'Tag to remove' : 'Tag to add'}</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.tag || ''} onChange={(e) => onUpdate({ tag: e.target.value, description: `Tag: ${e.target.value}` })} placeholder="e.g. VIP, confirmed" /></div>
          )}
          {d.actionType === 'assign_agent' && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Agent name</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.agent || ''} onChange={(e) => onUpdate({ agent: e.target.value, description: `Assign: ${e.target.value}` })} placeholder="e.g. support-team" /></div>
          )}
        </>)}

        {t === 'delayFlow' && (
          <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Wait (minutes)</label><input type="number" className="w-full border rounded-lg px-3 py-2 text-sm" value={d.minutes || 10} min={1} onChange={(e) => onUpdate({ minutes: Math.max(1, Number(e.target.value) || 1) })} /></div>
        )}
      </div>
      {t !== 'startTrigger' && (
        <div className="p-4 border-t"><button className="w-full px-4 py-2.5 rounded-lg text-sm font-medium text-rose-600 border border-rose-200 hover:bg-rose-50 transition-colors flex items-center justify-center gap-2" onClick={onDelete}><Trash2 className="w-4 h-4" /> Delete this step</button></div>
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
