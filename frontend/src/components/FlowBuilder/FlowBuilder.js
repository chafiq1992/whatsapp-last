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
  ChevronRight, X, List, Package, Search,
  CheckCircle, FileText, BarChart2, MousePointerClick,
  Sparkles, Send, Loader2,
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

/* Helper: infer body variable placeholder names from a WhatsApp template */
function _inferBodyVarNamesFromTpl(tpl) {
  try {
    const comps = tpl?.components || [];
    const body = (Array.isArray(comps) ? comps : []).find(c => String(c?.type || '').toUpperCase() === 'BODY');
    if (!body) return [];
    const text = String(body?.text || '');
    const allMatches = text.match(/\{\{([^}]+)\}\}/g);
    if (!allMatches) return [];
    return [...new Set(allMatches)].map(m => m.replace(/^\{\{/, '').replace(/\}\}$/, '').trim());
  } catch { return []; }
}
function _getTemplateHeaderType(tpl) {
  try {
    const comps = Array.isArray(tpl?.components) ? tpl.components : [];
    const h = comps.find(c => String(c?.type || '').toUpperCase() === 'HEADER');
    return String(h?.format || '').toUpperCase(); // IMAGE | VIDEO | DOCUMENT | TEXT
  } catch { return ''; }
}

function _getTemplateButtons(tpl) {
  try {
    const comps = Array.isArray(tpl?.components) ? tpl.components : [];
    const btnComp = comps.find(c => String(c?.type || '').toUpperCase() === 'BUTTONS');
    if (!btnComp || !Array.isArray(btnComp.buttons)) return [];
    return btnComp.buttons.map((b, i) => ({
      id: String(b?.id || b?.text || `btn_${i}`).toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 24) || `btn_${i}`,
      text: String(b?.text || b?.id || `Button ${i + 1}`),
      type: String(b?.type || 'QUICK_REPLY').toUpperCase(),
    }));
  } catch { return []; }
}

const ACTION_CATEGORIES = [
  { id: 'whatsapp', label: 'WhatsApp Messaging', icon: <MessageSquare className="w-3.5 h-3.5" />, color: 'green' },
  { id: 'shopify',  label: 'Shopify Actions',    icon: <ShoppingCart className="w-3.5 h-3.5" />,  color: 'emerald' },
  { id: 'catalog',  label: 'Catalog & Orders',   icon: <Package className="w-3.5 h-3.5" />,       color: 'indigo' },
  { id: 'workflow', label: 'Workflow Control',   icon: <Zap className="w-3.5 h-3.5" />,           color: 'slate' },
];

const ACTION_CATALOG = [
  // ── WhatsApp Messaging ──
  { id: 'send_text',         label: 'Send Text Message',       icon: <MessageSquare className="w-4 h-4 text-blue-500" />,    type: 'send_whatsapp_text',            cat: 'whatsapp', desc: 'Send a plain WhatsApp text with variables' },
  { id: 'send_template',     label: 'Send WhatsApp Template',  icon: <FileText className="w-4 h-4 text-emerald-500" />,      type: 'send_whatsapp_template',        cat: 'whatsapp', desc: 'Send an approved template message' },
  { id: 'send_buttons',      label: 'Send Button Message',     icon: <MessageSquare className="w-4 h-4 text-indigo-500" />,  type: 'send_buttons',                  cat: 'whatsapp', desc: 'Interactive message with reply buttons' },
  { id: 'send_list',         label: 'Send List Message',       icon: <List className="w-4 h-4 text-teal-500" />,             type: 'send_list',                     cat: 'whatsapp', desc: 'Interactive list with selectable rows' },
  { id: 'send_image',        label: 'Send Image',              icon: <MessageSquare className="w-4 h-4 text-pink-500" />,    type: 'send_image',                    cat: 'whatsapp', desc: 'Send an image with optional caption' },
  { id: 'send_video',        label: 'Send Video',              icon: <MessageSquare className="w-4 h-4 text-rose-500" />,    type: 'send_video',                    cat: 'whatsapp', desc: 'Send a video with optional caption' },
  { id: 'send_audio',        label: 'Send Audio',              icon: <MessageSquare className="w-4 h-4 text-violet-500" />,  type: 'send_audio',                    cat: 'whatsapp', desc: 'Send a voice message or audio file' },
  // ── Shopify Actions ──
  { id: 'tag_customer',      label: 'Tag Customer',            icon: <Zap className="w-4 h-4 text-amber-500" />,             type: 'shopify_tag',                   cat: 'shopify',  desc: 'Add a tag to the Shopify customer' },
  { id: 'remove_tag',        label: 'Remove Tag',              icon: <Zap className="w-4 h-4 text-orange-500" />,            type: 'shopify_remove_tag',            cat: 'shopify',  desc: 'Remove a tag from the Shopify customer' },
  { id: 'order_confirm',     label: 'Confirmation Flow',       icon: <CheckCircle className="w-4 h-4 text-emerald-500" />,   type: 'order_confirmation_flow',       cat: 'shopify',  desc: 'Multi-step order confirmation with buttons' },
  { id: 'order_status',      label: 'Order Status Lookup',     icon: <Search className="w-4 h-4 text-sky-500" />,            type: 'shopify_order_status',           cat: 'shopify',  desc: 'Look up and send order status to customer' },
  // ── Catalog & Orders ──
  { id: 'catalog_item',      label: 'Send Catalog Item',       icon: <Package className="w-4 h-4 text-indigo-500" />,        type: 'send_catalog_item',             cat: 'catalog',  desc: 'Send a single product from your catalog' },
  { id: 'catalog_set',       label: 'Send Catalog Set',        icon: <Package className="w-4 h-4 text-purple-500" />,        type: 'send_catalog_set',              cat: 'catalog',  desc: 'Send a product set from your catalog' },
  { id: 'last_order_items',  label: 'Last Order Items + Audio', icon: <ShoppingCart className="w-4 h-4 text-pink-500" />,     type: 'send_last_order_catalog_items', cat: 'catalog',  desc: 'Send last order items as catalog cards + audio' },
  // ── Workflow Control ──
  { id: 'assign_agent',      label: 'Assign to Agent',         icon: <Zap className="w-4 h-4 text-cyan-500" />,              type: 'assign_agent',                  cat: 'workflow', desc: 'Route conversation to a specific agent' },
  { id: 'close_conversation',label: 'Close Conversation',      icon: <Ban className="w-4 h-4 text-slate-500" />,             type: 'close_conversation',            cat: 'workflow', desc: 'Mark conversation as resolved' },
  { id: 'exit',              label: 'Stop / Exit',             icon: <Ban className="w-4 h-4 text-rose-500" />,              type: 'exit',                          cat: 'workflow', desc: 'End the workflow here' },
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
function FlowsListView({ flows, onSelect, onNewFlow, onDelete, loading, stats }) {
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
            {flows.map((f) => {
              const s = (stats || {})[f.id] || {};
              const triggers = s.triggers || 0;
              const msgs = s.messages_sent || 0;
              const lastTs = s.last_trigger_ts;
              return (
                <div
                  key={f.id}
                  className="p-4 rounded-xl border border-slate-200 bg-white flex items-center justify-between hover:border-blue-300 hover:shadow-sm transition-all cursor-pointer group"
                  onClick={() => onSelect(f)}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <div className="text-sm font-semibold text-slate-800 group-hover:text-blue-600 transition-colors truncate">{f.name || f.id}</div>
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${f.enabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-500'}`}>
                        {f.enabled ? 'Active' : 'Inactive'}
                      </span>
                      {triggers > 0 && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-100 flex items-center gap-1">
                          <BarChart2 className="w-2.5 h-2.5" /> {triggers.toLocaleString()} triggers
                        </span>
                      )}
                      {msgs > 0 && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-green-50 text-green-600 border border-green-100 flex items-center gap-1">
                          <MessageSquare className="w-2.5 h-2.5" /> {msgs.toLocaleString()} sent
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 mt-1 flex items-center gap-3">
                      <span className="truncate">Trigger: {f.trigger?.source || 'whatsapp'} / {f.trigger?.event || 'incoming'}</span>
                      {lastTs && <span className="flex-shrink-0">Last run: {new Date(lastTs).toLocaleDateString()}</span>}
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
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   MAIN FlowBuilder component
   ═══════════════════════════════════════════════════════════ */
function FlowBuilderCanvas({ initialFlow, templates, onBack, onSaveToBackend, allRules, flowStats }) {
  const [nodes, setNodes] = useState(initialFlow?.nodes || []);
  const [edges, setEdges] = useState(initialFlow?.edges || []);
  const [flowName, setFlowName] = useState(initialFlow?.meta?.name || '');
  const [flowEnabled, setFlowEnabled] = useState(initialFlow?.meta?.enabled !== false);
  const [flowId, setFlowId] = useState(initialFlow?.meta?.ruleId || '');
  const [saving, setSaving] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [sidePanel, setSidePanel] = useState(null); // 'trigger_picker' | 'step_picker' | 'node_editor'
  const [addAfterNodeId, setAddAfterNodeId] = useState(null);

  // Current flow-level stats (triggers, messages_sent)
  const flowStat = flowStats || {};

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
    // Use setNodes updater to read fresh nodes (avoids stale closure)
    setNodes(currentNodes => {
      const n = currentNodes.find(nd => nd.id === nodeId);
      if (n && n.type !== 'addStep' && n.type !== 'addStepFlow') {
        setSidePanel('node_editor');
      }
      return currentNodes; // no mutation
    });
  }, []);

  /* Inject callbacks into nodes */
  const nodesWithCallbacks = useMemo(() => {
    return nodes.map(n => ({
      ...n,
      data: {
        ...n.data,
        onSelect: () => {
          if (n.type === 'startTrigger' && !n.data.configured) {
            onTriggerSelect();
          } else if (n.type === 'addStep' || n.type === 'addStepFlow') {
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
        templateVars: config.templateVars || [],
        templateHeaderUrl: config.templateHeaderUrl || '',
        templateHeaderType: config.templateHeaderType || '',
        tag: config.tag || '',
        description: config.description || '',
        // Buttons
        buttonsText: config.buttonsText || '',
        buttonsLines: config.buttonsLines || '',
        // List
        listText: config.listText || '',
        listButtonText: config.listButtonText || 'Choose',
        listSectionTitle: config.listSectionTitle || '',
        listRowsLines: config.listRowsLines || '',
        // Image / Video
        imageUrl: config.imageUrl || '',
        videoUrl: config.videoUrl || '',
        caption: config.caption || '',
        // Audio
        audioUrl: config.audioUrl || '',
        // Catalog
        catalogItemRetailerId: config.catalogItemRetailerId || '',
        catalogItemCaption: config.catalogItemCaption || '',
        catalogSetId: config.catalogSetId || '',
        catalogSetCaption: config.catalogSetCaption || '',
        // Last order items
        lastOrderItemsMax: config.lastOrderItemsMax || 10,
        lastOrderAudioUrl: config.lastOrderAudioUrl || '',
        // Confirmation flow
        ocEntryGateMode: config.ocEntryGateMode || 'all',
        ocConfirmTitles: config.ocConfirmTitles || 'تأكيد الطلب\nتاكيد الطلب',
        ocChangeTitles: config.ocChangeTitles || 'تغيير المعلومات\nتغير المعلومات',
        ocTalkTitles: config.ocTalkTitles || 'تكلم مع العميل',
        ocConfirmAudioUrl: config.ocConfirmAudioUrl || '',
        ocChangeAudioUrl: config.ocChangeAudioUrl || '',
        ocTalkAudioUrl: config.ocTalkAudioUrl || '',
        ocSendItems: config.ocSendItems !== false,
        ocMaxItems: config.ocMaxItems || 10,
        // Agent
        agent: config.agent || '',
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

    // FIX 1: Do NOT auto-select the new step node
    setSidePanel(null);
    setAddAfterNodeId(null);
    setSelectedNodeId(null);
  }, [addAfterNodeId, nodes]);

  /* ── Spawn button child nodes from a template ────────── */
  const spawnButtonChildNodes = useCallback((actionNodeId, buttonDefs) => {
    setNodes(prev => {
      const actionNode = prev.find(n => n.id === actionNodeId);
      if (!actionNode) return prev;

      // Remove any old button-reply children
      const oldChildIds = actionNode.data?.buttonChildIds || [];
      const withoutOld = prev.filter(n => !oldChildIds.includes(n.id));

      if (!buttonDefs || buttonDefs.length === 0) {
        // Patch action node to remove buttonChildIds
        return withoutOld.map(n => n.id === actionNodeId
          ? { ...n, data: { ...n.data, buttonChildIds: [], buttonDefs: [] } }
          : n
        );
      }

      const ax = actionNode.position.x;
      const ay = actionNode.position.y;
      const total = buttonDefs.length;
      const spread = 220;
      const startX = ax - ((total - 1) * spread) / 2;

      const newChildIds = [];
      const newChildNodes = buttonDefs.map((btn, i) => {
        const childId = uid();
        newChildIds.push(childId);
        return rfNode(childId, 'buttonReply', startX + i * spread, ay + 320, {
          buttonText: btn.text,
          buttonId: btn.id,
          buttonIndex: i,
          replyActionType: '',
          replyActionLabel: '',
          replyText: '',
          replyTemplateName: '',
        });
      });

      const patched = withoutOld.map(n => n.id === actionNodeId
        ? { ...n, data: { ...n.data, buttonChildIds: newChildIds, buttonDefs } }
        : n
      );
      return [...patched, ...newChildNodes];
    });

    setEdges(prev => {
      // Get fresh action node data from latest node state snapshot (we use updater above)
      // Remove old button edges from this action node
      const withoutOld = prev.filter(e => !(e.source === actionNodeId && String(e.sourceHandle || '').startsWith('btn_')));
      return withoutOld;
    });

    // Add new edges in a separate update after nodes settle
    setTimeout(() => {
      setNodes(currentNodes => {
        const actionNode = currentNodes.find(n => n.id === actionNodeId);
        if (!actionNode) return currentNodes;
        const childIds = actionNode.data?.buttonChildIds || [];
        setEdges(prev => {
          const withoutOld = prev.filter(e => !(e.source === actionNodeId && String(e.sourceHandle || '').startsWith('btn_')));
          const newEdges = childIds.map((childId, i) => rfEdge(actionNodeId, childId, `btn_${i}`));
          return [...withoutOld, ...newEdges];
        });
        return currentNodes;
      });
    }, 0);
  }, []);


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
    // When template name changes, auto-spawn or remove button child nodes
    if ('templateName' in patch) {
      const tpl = (templates || []).find(t => t.name === patch.templateName);
      const btns = _getTemplateButtons(tpl);
      spawnButtonChildNodes(nodeId, btns);
    }
  }, [templates, spawnButtonChildNodes]);

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
            // Build components with header + body vars
            const comps = [];
            const headerUrl = String(d.templateHeaderUrl || '').trim();
            const headerType = String(d.templateHeaderType || '').toUpperCase();
            if (headerUrl && ['IMAGE', 'VIDEO', 'DOCUMENT'].includes(headerType)) {
              if (headerType === 'IMAGE') comps.push({ type: 'header', parameters: [{ type: 'image', image: { link: headerUrl } }] });
              else if (headerType === 'VIDEO') comps.push({ type: 'header', parameters: [{ type: 'video', video: { link: headerUrl } }] });
              else comps.push({ type: 'header', parameters: [{ type: 'document', document: { link: headerUrl } }] });
            }
            const tVars = Array.isArray(d.templateVars) ? d.templateVars : [];
            const bodyParams = tVars.filter(v => String(v || '').trim()).map(v => ({ type: 'text', text: String(v) }));
            if (bodyParams.length) comps.push({ type: 'body', parameters: bodyParams });
            actions.push({
              type: 'send_whatsapp_template', to: '{{ phone }}',
              template_name: d.templateName || '', language: d.templateLanguage || 'en',
              components: comps,
            });
          } else if (at === 'send_buttons') {
            const lines = String(d.buttonsLines || '').split(/\r?\n/g).map(x => x.trim()).filter(Boolean);
            const btns = lines.map((ln, i) => {
              const parts = ln.split('|'); let id = parts[0]?.trim(); let title = parts.slice(1).join('|').trim();
              if (!title && id) { title = id; id = title.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 24) || `btn_${i+1}`; }
              return id && title ? { id, title } : null;
            }).filter(Boolean);
            if (btns.length) actions.push({ type: 'send_buttons', to: '{{ phone }}', text: d.buttonsText || '', buttons: btns });
          } else if (at === 'send_list') {
            const rowLines = String(d.listRowsLines || '').split(/\r?\n/g).map(x => x.trim()).filter(Boolean);
            const rows = rowLines.map(ln => {
              const p = ln.split('|'); const id = p[0]?.trim(); const title = p[1]?.trim(); const desc = p.slice(2).join('|').trim();
              if (!id || !title) return null;
              const row = { id, title }; if (desc) row.description = desc; return row;
            }).filter(Boolean);
            if (rows.length) actions.push({ type: 'send_list', to: '{{ phone }}', text: d.listText || '', button_text: d.listButtonText || 'Choose', sections: [{ ...(d.listSectionTitle ? { title: d.listSectionTitle } : {}), rows }] });
          } else if (at === 'send_image') {
            actions.push({ type: 'send_image', to: '{{ phone }}', image_url: d.imageUrl || '', caption: d.caption || '' });
          } else if (at === 'send_video') {
            actions.push({ type: 'send_video', to: '{{ phone }}', video_url: d.videoUrl || '', caption: d.caption || '' });
          } else if (at === 'send_audio') {
            actions.push({ type: 'send_audio_url', to: '{{ phone }}', audio_url: d.audioUrl || '' });
          } else if (at === 'shopify_tag') {
            actions.push({ type: 'add_tag', tag: d.tag || '' });
          } else if (at === 'shopify_remove_tag') {
            actions.push({ type: 'remove_tag', tag: d.tag || '' });
          } else if (at === 'order_confirmation_flow') {
            const listFromLines = s => String(s || '').split(/\r?\n/g).map(x => x.trim()).filter(Boolean);
            const comps = [];
            const headerUrl = String(d.templateHeaderUrl || '').trim();
            const headerType = String(d.templateHeaderType || '').toUpperCase();
            if (headerUrl && ['IMAGE','VIDEO','DOCUMENT'].includes(headerType)) {
              if (headerType === 'IMAGE') comps.push({ type: 'header', parameters: [{ type: 'image', image: { link: headerUrl } }] });
              else if (headerType === 'VIDEO') comps.push({ type: 'header', parameters: [{ type: 'video', video: { link: headerUrl } }] });
              else comps.push({ type: 'header', parameters: [{ type: 'document', document: { link: headerUrl } }] });
            }
            const tVars = Array.isArray(d.templateVars) ? d.templateVars : [];
            const bodyParams = tVars.filter(v => String(v||'').trim()).map(v => ({ type: 'text', text: String(v) }));
            if (bodyParams.length) comps.push({ type: 'body', parameters: bodyParams });
            actions.push({
              type: 'order_confirmation_flow', to: '{{ phone }}',
              template_name: d.templateName || '', language: d.templateLanguage || 'en', components: comps,
              entry_gate_mode: d.ocEntryGateMode || 'all',
              confirm_titles: listFromLines(d.ocConfirmTitles), change_titles: listFromLines(d.ocChangeTitles), talk_titles: listFromLines(d.ocTalkTitles),
              confirm_audio_url: d.ocConfirmAudioUrl || '', change_audio_url: d.ocChangeAudioUrl || '', talk_audio_url: d.ocTalkAudioUrl || '',
              send_items: !!d.ocSendItems, max_items: Number(d.ocMaxItems || 10),
            });
          } else if (at === 'shopify_order_status') {
            actions.push({ type: 'shopify_order_status' });
          } else if (at === 'send_catalog_item') {
            actions.push({ type: 'send_catalog_item', to: '{{ phone }}', retailer_id: d.catalogItemRetailerId || '', caption: d.catalogItemCaption || '' });
          } else if (at === 'send_catalog_set') {
            actions.push({ type: 'send_catalog_set', to: '{{ phone }}', set_id: d.catalogSetId || '', caption: d.catalogSetCaption || '' });
          } else if (at === 'send_last_order_catalog_items') {
            actions.push({ type: 'send_last_order_catalog_items', to: '{{ phone }}', max_items: Number(d.lastOrderItemsMax || 10) });
            if (String(d.lastOrderAudioUrl || '').trim()) actions.push({ type: 'send_audio_url', to: '{{ phone }}', audio_url: d.lastOrderAudioUrl });
          } else if (at === 'assign_agent') {
            actions.push({ type: 'assign_agent', agent: d.agent || '' });
          } else if (at === 'close_conversation') {
            actions.push({ type: 'close_conversation' });
          } else if (at === 'exit') {
            actions.push({ type: 'exit' });
          }
          // Collect button_actions from buttonReply child nodes
          const childIds = target.data?.buttonChildIds || [];
          if (childIds.length > 0 && actions.length > 0) {
            const lastAction = actions[actions.length - 1];
            const btnActions = [];
            for (const cid of childIds) {
              const childNode = nodes.find(n => n.id === cid && n.type === 'buttonReply');
              if (!childNode) continue;
              const cd = childNode.data || {};
              if (!cd.replyActionType) continue;
              const btnAction = { button_id: cd.buttonId || '', button_text: cd.buttonText || '', action: { type: cd.replyActionType } };
              const ra = cd.replyActionType;
              if (ra === 'send_whatsapp_text') { btnAction.action.text = cd.replyText || ''; btnAction.action.to = '{{ phone }}'; }
              else if (ra === 'send_whatsapp_template') {
                btnAction.action.template_name = cd.replyTemplateName || '';
                btnAction.action.language = cd.replyTemplateLanguage || 'en';
                btnAction.action.to = '{{ phone }}';
                const rvars = Array.isArray(cd.replyTemplateVars) ? cd.replyTemplateVars : [];
                const rbp = rvars.filter(v => String(v || '').trim()).map(v => ({ type: 'text', text: String(v) }));
                if (rbp.length) btnAction.action.components = [{ type: 'body', parameters: rbp }];
              }
              else if (ra === 'send_catalog_set') { btnAction.action.to = '{{ phone }}'; btnAction.action.set_id = cd.replyCatalogSetId || ''; btnAction.action.caption = cd.replyCatalogSetCaption || ''; }
              else if (ra === 'send_catalog_item') { btnAction.action.to = '{{ phone }}'; btnAction.action.retailer_id = cd.replyCatalogItemRetailerId || ''; btnAction.action.caption = cd.replyCatalogItemCaption || ''; }
              else if (ra === 'send_audio') { btnAction.action.to = '{{ phone }}'; btnAction.action.audio_url = cd.replyAudioUrl || ''; }
              else if (ra === 'send_image') { btnAction.action.to = '{{ phone }}'; btnAction.action.image_url = cd.replyImageUrl || ''; btnAction.action.caption = cd.replyImageCaption || ''; }
              else if (ra === 'send_video') { btnAction.action.to = '{{ phone }}'; btnAction.action.video_url = cd.replyVideoUrl || ''; btnAction.action.caption = cd.replyVideoCaption || ''; }
              else if (ra === 'send_list') {
                btnAction.action.to = '{{ phone }}'; btnAction.action.text = cd.replyListText || '';
                btnAction.action.button_text = cd.replyListButtonText || 'Choose';
                const rlRows = String(cd.replyListRowsLines || '').split(/\r?\n/g).map(x => x.trim()).filter(Boolean);
                const rows = rlRows.map(ln => { const p = ln.split('|'); const id = p[0]?.trim(); const title = p[1]?.trim(); const desc = p.slice(2).join('|').trim(); if (!id || !title) return null; const row = { id, title }; if (desc) row.description = desc; return row; }).filter(Boolean);
                if (rows.length) btnAction.action.sections = [{ ...(cd.replyListSectionTitle ? { title: cd.replyListSectionTitle } : {}), rows }];
              }
              else if (ra === 'send_buttons') {
                btnAction.action.to = '{{ phone }}'; btnAction.action.text = cd.replyButtonsText || '';
                const blines = String(cd.replyButtonsLines || '').split(/\r?\n/g).map(x => x.trim()).filter(Boolean);
                const btns = blines.map((ln, i) => { const parts = ln.split('|'); let id = parts[0]?.trim(); let title = parts.slice(1).join('|').trim(); if (!title && id) { title = id; id = title.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 24) || `btn_${i+1}`; } return id && title ? { id, title } : null; }).filter(Boolean);
                if (btns.length) btnAction.action.buttons = btns;
              }
              else if (ra === 'send_last_order_catalog_items') { btnAction.action.to = '{{ phone }}'; btnAction.action.max_items = Number(cd.replyLastOrderItemsMax || 10); }
              else if (ra === 'shopify_order_status') { /* no config needed */ }
              else if (ra === 'shopify_tag') { btnAction.action.tag = cd.replyTag || ''; }
              else if (ra === 'shopify_remove_tag') { btnAction.action.tag = cd.replyTag || ''; }
              else if (ra === 'assign_agent') { btnAction.action.agent = cd.replyAgent || ''; }
              else if (ra === 'close_conversation') { /* no config */ }
              else if (ra === 'exit') { /* no config */ }
              btnActions.push(btnAction);
            }
            if (btnActions.length > 0) {
              lastAction.button_actions = btnActions;
            }
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
          {/* Metrics badges */}
          {(flowStat.triggers > 0 || flowStat.messages_sent > 0) && (
            <div className="flex items-center gap-1.5">
              {flowStat.triggers > 0 && (
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-100 flex items-center gap-1">
                  <BarChart2 className="w-2.5 h-2.5" /> {flowStat.triggers.toLocaleString()} triggers
                </span>
              )}
              {flowStat.messages_sent > 0 && (
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-green-50 text-green-600 border border-green-100 flex items-center gap-1">
                  <MessageSquare className="w-2.5 h-2.5" /> {flowStat.messages_sent.toLocaleString()} sent
                </span>
              )}
            </div>
          )}
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
                onSpawnButtons={(btns) => spawnButtonChildNodes(selectedNode.id, btns)}
              />
            )}
          </div>
        )}
      </div>

      {/* Flow Drafter AI chat window */}
      <FlowDrafterChat
        nodes={nodes}
        setNodes={setNodes}
        edges={edges}
        setEdges={setEdges}
        triggerSource={currentTriggerNode?.data?.source}
        triggerEvent={currentTriggerNode?.data?.event}
      />
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   Flow Drafter — AI-powered draft generation chat
   ═══════════════════════════════════════════════════════════ */
function FlowDrafterChat({ nodes, setNodes, edges, setEdges, triggerSource, triggerEvent }) {
  const [open, setOpen] = React.useState(false);
  const [messages, setMessages] = React.useState([{ role: 'assistant', text: 'Hi! Describe the flow you want and I\'ll draft it for you. ✨' }]);
  const [input, setInput] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const bottomRef = React.useRef(null);

  React.useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const sendPrompt = async () => {
    const prompt = input.trim();
    if (!prompt || loading) return;
    setInput('');
    setMessages(prev => [...prev.slice(-8), { role: 'user', text: prompt }]);
    setLoading(true);
    try {
      const res = await api.post('/api/flow-drafter', { prompt, triggerSource: triggerSource || '', triggerEvent: triggerEvent || '' });
      const flow = res.data?.flow;
      if (flow?.nodes?.length) {
        // Remap node IDs to avoid collisions
        const ts = Date.now();
        const idMap = {};
        const newNodes = flow.nodes.map((n, i) => {
          const newId = `fd_${ts}_${i}`;
          idMap[n.id] = newId;
          return { ...n, id: newId, draggable: true, position: n.position || { x: 0, y: i * 200 } };
        });
        const newEdges = (flow.edges || []).map(e => ({
          ...e,
          id: `e_${idMap[e.source] || e.source}_${idMap[e.target] || e.target}_${e.sourceHandle || 'default'}`,
          source: idMap[e.source] || e.source,
          target: idMap[e.target] || e.target,
          type: 'smoothstep', animated: true,
          style: { stroke: '#94a3b8', strokeWidth: 2 },
          markerEnd: { type: 'arrowclosed', color: '#94a3b8' },
        }));
        setNodes(newNodes);
        setEdges(newEdges);
        setMessages(prev => [...prev, { role: 'assistant', text: `✅ Draft created with ${newNodes.length} nodes! Review the canvas and edit as needed.` }]);
      } else {
        setMessages(prev => [...prev, { role: 'assistant', text: '⚠️ No flow was generated. Try being more specific.' }]);
      }
    } catch (err) {
      const detail = err?.response?.data?.detail || err.message || 'Unknown error';
      setMessages(prev => [...prev, { role: 'assistant', text: `❌ ${detail}` }]);
    } finally {
      setLoading(false);
    }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full bg-gradient-to-br from-violet-600 to-indigo-600 text-white shadow-2xl hover:shadow-violet-500/40 hover:scale-110 transition-all flex items-center justify-center group"
        title="Flow Drafter AI"
      >
        <Sparkles className="w-6 h-6 group-hover:animate-pulse" />
      </button>
    );
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 w-[360px] h-[480px] rounded-2xl bg-white border border-slate-200 shadow-2xl flex flex-col overflow-hidden" style={{ boxShadow: '0 25px 60px -12px rgba(124, 58, 237, 0.25)' }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-violet-600 to-indigo-600 text-white">
        <div className="flex items-center gap-2">
          <Sparkles className="w-5 h-5" />
          <span className="font-semibold text-sm">Flow Drafter</span>
          <span className="text-[10px] opacity-70 bg-white/20 px-1.5 py-0.5 rounded-full">AI</span>
        </div>
        <button onClick={() => setOpen(false)} className="p-1 rounded-lg hover:bg-white/20 transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3 bg-gradient-to-b from-slate-50 to-white">
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[85%] px-3.5 py-2.5 rounded-2xl text-sm leading-relaxed ${
              m.role === 'user'
                ? 'bg-gradient-to-br from-violet-600 to-indigo-600 text-white rounded-br-md'
                : 'bg-white border border-slate-200 text-slate-700 rounded-bl-md shadow-sm'
            }`}>
              {m.text}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-white border border-slate-200 text-slate-500 px-4 py-3 rounded-2xl rounded-bl-md shadow-sm flex items-center gap-2 text-sm">
              <Loader2 className="w-4 h-4 animate-spin text-violet-500" /> Generating flow…
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="px-3 py-3 border-t bg-white">
        <div className="flex gap-2">
          <input
            className="flex-1 px-3.5 py-2.5 text-sm rounded-xl border border-slate-200 bg-slate-50 focus:outline-none focus:ring-2 focus:ring-violet-500/30 focus:border-violet-400 placeholder:text-slate-400 transition-all"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendPrompt()}
            placeholder="Describe your flow…"
            disabled={loading}
          />
          <button
            onClick={sendPrompt}
            disabled={loading || !input.trim()}
            className="px-3 py-2.5 rounded-xl bg-gradient-to-r from-violet-600 to-indigo-600 text-white disabled:opacity-40 hover:shadow-lg hover:shadow-violet-500/25 transition-all flex items-center"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
        <p className="text-[10px] text-slate-400 mt-1.5 text-center">Drafts only — review before saving</p>
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
  const [openCats, setOpenCats] = React.useState({ whatsapp: true, shopify: true, catalog: true, workflow: true });
  const toggleCat = (id) => setOpenCats(prev => ({ ...prev, [id]: !prev[id] }));
  const catColors = { whatsapp: { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-700', hover: 'hover:bg-green-50 hover:border-green-300', btnBg: 'bg-green-50', btnText: 'text-green-600' }, shopify: { bg: 'bg-emerald-50', border: 'border-emerald-200', text: 'text-emerald-700', hover: 'hover:bg-emerald-50 hover:border-emerald-300', btnBg: 'bg-emerald-50', btnText: 'text-emerald-600' }, catalog: { bg: 'bg-indigo-50', border: 'border-indigo-200', text: 'text-indigo-700', hover: 'hover:bg-indigo-50 hover:border-indigo-300', btnBg: 'bg-indigo-50', btnText: 'text-indigo-600' }, workflow: { bg: 'bg-slate-50', border: 'border-slate-200', text: 'text-slate-700', hover: 'hover:bg-slate-50 hover:border-slate-300', btnBg: 'bg-slate-100', btnText: 'text-slate-600' } };
  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">Add a step</h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
      </div>
      <div className="p-4 space-y-3 overflow-y-auto flex-1">
        {/* Condition */}
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1">Conditions</div>
        <button className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-amber-300 hover:bg-amber-50 transition-all flex items-center gap-3 group" onClick={() => onAddStep('condition')}>
          <div className="p-2 rounded-lg bg-amber-50 text-amber-600 group-hover:bg-amber-100"><SplitSquareHorizontal className="w-5 h-5" /></div>
          <div><div className="text-sm font-semibold text-slate-700">Condition</div><div className="text-xs text-slate-400">Check a value before continuing</div></div>
        </button>

        {/* Delay */}
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 mt-4">Timing</div>
        <button className="w-full text-left px-4 py-3 rounded-xl border border-slate-200 hover:border-violet-300 hover:bg-violet-50 transition-all flex items-center gap-3 group" onClick={() => onAddStep('delay')}>
          <div className="p-2 rounded-lg bg-violet-50 text-violet-600 group-hover:bg-violet-100"><Timer className="w-5 h-5" /></div>
          <div><div className="text-sm font-semibold text-slate-700">Delay</div><div className="text-xs text-slate-400">Wait before the next step</div></div>
        </button>

        {/* Action categories */}
        <div className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 mt-4">Actions</div>
        {ACTION_CATEGORIES.map(cat => {
          const items = ACTION_CATALOG.filter(a => a.cat === cat.id);
          if (!items.length) return null;
          const cc = catColors[cat.id] || catColors.workflow;
          const isOpen = openCats[cat.id] !== false;
          return (
            <div key={cat.id} className={`rounded-xl border ${cc.border} overflow-hidden`}>
              <button type="button" className={`w-full flex items-center justify-between px-3 py-2.5 ${cc.bg} transition-colors`} onClick={() => toggleCat(cat.id)}>
                <div className={`flex items-center gap-2 text-xs font-bold uppercase tracking-widest ${cc.text}`}>
                  {cat.icon} {cat.label}
                </div>
                <ChevronRight className={`w-4 h-4 ${cc.text} transition-transform ${isOpen ? 'rotate-90' : ''}`} />
              </button>
              {isOpen && (
                <div className="p-2 space-y-1 bg-white">
                  {items.map(a => (
                    <button key={a.id} className={`w-full text-left px-3 py-2.5 rounded-lg border border-transparent ${cc.hover} transition-all flex items-center gap-3 group`} onClick={() => onAddStep('action', { type: a.type })}>
                      <div className={`p-1.5 rounded-lg ${cc.btnBg} ${cc.btnText}`}>{a.icon}</div>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-slate-700">{a.label}</div>
                        {a.desc && <div className="text-[11px] text-slate-400 truncate">{a.desc}</div>}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
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


/* ═══════════════════════════════════════════════════════════
   GcsMediaUpload — drag-and-drop upload to GCS
   ═══════════════════════════════════════════════════════════ */
function GcsMediaUpload({ label, accept, value, onChange }) {
  const [uploading, setUploading] = React.useState(false);
  const [err, setErr] = React.useState('');
  const inputRef = React.useRef();

  const doUpload = async (file) => {
    if (!file) return;
    setUploading(true); setErr('');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await api.post('/admin/upload-media', fd, { headers: { 'Content-Type': 'multipart/form-data' } });
      if (res?.data?.url) { onChange(res.data.url); }
      else setErr('Upload failed — no URL returned');
    } catch (e) {
      setErr(String(e?.response?.data?.detail || e?.message || 'Upload failed'));
    } finally {
      setUploading(false);
    }
  };

  const onDrop = (e) => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) doUpload(f); };
  const onDragOver = (e) => e.preventDefault();

  return (
    <div className="space-y-2">
      <label className="text-xs font-semibold text-slate-500 block">{label} URL</label>
      <div
        className={`border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition-colors ${uploading ? 'border-indigo-300 bg-indigo-50' : 'border-slate-200 hover:border-indigo-400 hover:bg-indigo-50'}`}
        onClick={() => inputRef.current?.click()}
        onDrop={onDrop}
        onDragOver={onDragOver}
      >
        {uploading ? (
          <div className="flex items-center justify-center gap-2 text-indigo-600 text-sm">
            <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>
            Uploading…
          </div>
        ) : (
          <div className="text-slate-500 text-xs">
            <div className="text-2xl mb-1">☁️</div>
            <span className="font-medium text-indigo-600">Click or drag</span> to upload {label.toLowerCase()}<br/>
            <span className="text-[10px] text-slate-400">Max 50 MB · Uploads to GCS</span>
          </div>
        )}
      </div>
      <input ref={inputRef} type="file" accept={accept} className="hidden" onChange={(e) => doUpload(e.target.files?.[0])} />
      <input
        className="w-full border rounded-lg px-3 py-2 text-sm"
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Or paste URL directly…"
      />
      {err && <div className="text-xs text-rose-600 mt-1">{err}</div>}
      {value && !uploading && (
        <div className="text-[10px] text-emerald-600 truncate">✓ {value}</div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   VariableSearchPicker — searchable, source-aware variable picker
   ═══════════════════════════════════════════════════════════ */
const ALL_VARIABLES_BY_SOURCE = {
  whatsapp: [
    { label: 'Customer name', value: '{{customer_name}}' },
    { label: 'Customer phone', value: '{{customer_phone}}' },
    { label: 'Message text', value: '{{message_text}}' },
    { label: 'Message timestamp', value: '{{message_timestamp}}' },
    { label: 'Button title clicked', value: '{{button_title}}' },
    { label: 'List reply title', value: '{{list_reply_title}}' },
  ],
  shopify: [
    { label: 'Order ID', value: '{{order_id}}' },
    { label: 'Order number', value: '{{order_number}}' },
    { label: 'Order status', value: '{{order_status}}' },
    { label: 'Order total', value: '{{order_total_price}}' },
    { label: 'Order items count', value: '{{order_items_count}}' },
    { label: 'Order tracking URL', value: '{{order_tracking_url}}' },
    { label: 'Product title', value: '{{product_title}}' },
    { label: 'Product price', value: '{{product_price}}' },
    { label: 'Discount code', value: '{{discount_code}}' },
    { label: 'Shopify customer name', value: '{{shopify_customer_name}}' },
    { label: 'Shopify customer email', value: '{{shopify_customer_email}}' },
    { label: 'First order date', value: '{{first_order_date}}' },
    { label: 'Last order date', value: '{{last_order_date}}' },
    { label: 'Total orders', value: '{{total_orders}}' },
    { label: 'Total spent', value: '{{total_spent}}' },
  ],
  delivery: [
    { label: 'Delivery status', value: '{{delivery_status}}' },
    { label: 'Tracking number', value: '{{tracking_number}}' },
    { label: 'Estimated delivery', value: '{{estimated_delivery}}' },
    { label: 'Driver name', value: '{{driver_name}}' },
  ],
};

function VariableSearchPicker({ onInsert }) {
  const [open, setOpen] = React.useState(false);
  const [source, setSource] = React.useState('whatsapp');
  const [q, setQ] = React.useState('');
  const vars = ALL_VARIABLES_BY_SOURCE[source] || [];
  const filtered = q ? vars.filter(v => v.label.toLowerCase().includes(q.toLowerCase()) || v.value.toLowerCase().includes(q.toLowerCase())) : vars;

  return (
    <div className="relative">
      <button
        type="button"
        className="text-xs text-indigo-600 font-medium hover:underline flex items-center gap-1 mt-1"
        onClick={() => setOpen(o => !o)}
      >
        <span>{'{ }'}</span> Insert variable
      </button>
      {open && (
        <div className="absolute z-50 top-full left-0 mt-1 w-72 bg-white border border-slate-200 rounded-xl shadow-xl p-2">
          <div className="flex gap-1 mb-2">
            {Object.keys(ALL_VARIABLES_BY_SOURCE).map(src => (
              <button key={src} type="button"
                className={`flex-1 text-xs py-1 rounded-lg font-medium capitalize transition-colors ${source === src ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}
                onClick={() => { setSource(src); setQ(''); }}
              >{src}</button>
            ))}
          </div>
          <input
            className="w-full border rounded-lg px-2 py-1.5 text-xs mb-2"
            placeholder="Search variables…"
            value={q}
            onChange={e => setQ(e.target.value)}
            autoFocus
          />
          <div className="max-h-48 overflow-y-auto space-y-0.5">
            {filtered.map(v => (
              <button key={v.value} type="button"
                className="w-full text-left px-2 py-1.5 rounded-lg text-xs hover:bg-indigo-50 flex items-center justify-between group"
                onClick={() => { onInsert(v.value); setOpen(false); setQ(''); }}
              >
                <span className="text-slate-700">{v.label}</span>
                <span className="text-slate-400 font-mono group-hover:text-indigo-500">{v.value}</span>
              </button>
            ))}
            {filtered.length === 0 && <div className="text-xs text-slate-400 text-center py-2">No variables found</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function NodeEditorPanel({ node, templates, onClose, onUpdate, onDelete, onSelectTrigger, triggerSource, triggerEvent, onSpawnButtons }) {
  const d = node.data || {};
  const t = node.type;
  const [customField, setCustomField] = React.useState('');
  const trigVars = React.useMemo(() => getVariablesForTrigger(triggerSource, triggerEvent), [triggerSource, triggerEvent]);
  const insertVar = (v) => { const cur = d.text || ''; onUpdate({ text: cur + v, description: (cur + v).slice(0, 50) }); };

  return (
    <>
      <div className="flex items-center justify-between p-4 border-b">
        <h3 className="font-semibold text-slate-800">
          {t === 'startTrigger' ? 'Edit Trigger'
            : t === 'conditionFlow' ? 'Edit Condition'
            : t === 'delayFlow' ? 'Edit Delay'
            : t === 'buttonReply' ? 'Button Reply Action'
            : 'Edit Action'}
        </h3>
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
              {ACTION_CATEGORIES.map(cat => {
                const items = ACTION_CATALOG.filter(a => a.cat === cat.id);
                return (<optgroup key={cat.id} label={cat.label}>{items.map(a => (<option key={a.id} value={a.type}>{a.label}</option>))}</optgroup>);
              })}
            </select>
          </div>

          {/* ── Send Text ── */}
          {d.actionType === 'send_whatsapp_text' && (
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Message text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-28 resize-none" value={d.text || ''} onChange={(e) => onUpdate({ text: e.target.value, description: e.target.value.slice(0, 50) + (e.target.value.length > 50 ? '…' : '') })} placeholder="Type your message… Click variables below to insert" />
              <div className="flex justify-end mt-1 mb-2">
                <button type="button" className="text-xl opacity-70 hover:opacity-100 transition-opacity" onClick={() => onUpdate({ _showEmoji: !d._showEmoji })}>😀</button>
              </div>
              {d._showEmoji && (<div className="mb-3 border rounded-xl overflow-hidden shadow-sm"><EmojiPicker width="100%" height={300} onEmojiClick={(ev) => insertVar(ev.emoji)} /></div>)}
              <PlatformVariableSelector onInsert={insertVar} />
            </div>
          )}

          {/* ── Send Template (RICH) ── */}
          {(d.actionType === 'send_whatsapp_template' || d.actionType === 'order_confirmation_flow') && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Template</label>
              <select className="w-full border rounded-lg px-3 py-2 text-sm" value={d.templateName || ''} onChange={(e) => {
                const tn = e.target.value;
                const tpl = (templates || []).find(t => t.name === tn);
                const lang = tpl?.language || 'en';
                const varNames = _inferBodyVarNamesFromTpl(tpl);
                const tplVars = varNames.map(() => '');
                const headerType = _getTemplateHeaderType(tpl);
                onUpdate({ templateName: tn, templateLanguage: lang, templateVars: tplVars, templateHeaderType: headerType, templateHeaderUrl: '', description: `Template: ${tn}` });
              }}>
                <option value="">Select a template…</option>
                {(templates || []).filter(tp => String(tp.status || '').toLowerCase() === 'approved').map(tp => (
                  <option key={tp.name + '_' + tp.language} value={tp.name}>{tp.name} ({tp.language})</option>
                ))}
              </select>
            </div>
            {d.templateName && (<>
              <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs">
                <span className="font-semibold text-emerald-800">Language:</span>
                <span className="text-emerald-600 ml-1 font-mono">{d.templateLanguage || 'en'}</span>
                <span className="text-emerald-400 ml-2">(auto-detected)</span>
              </div>
              {/* Variable slots */}
              {(d.templateVars || []).length > 0 && (
                <div>
                  <label className="text-xs font-semibold text-slate-500 mb-2 block">Body Variables ({(d.templateVars || []).length})</label>
                  {(d.templateVars || []).map((v, i) => (
                    <div key={i} className="flex items-center gap-2 mb-2">
                      <span className="text-xs text-slate-400 font-mono w-10 flex-shrink-0">{`{{${i+1}}}`}</span>
                      <input className="flex-1 border rounded-lg px-3 py-1.5 text-sm" value={v} onChange={(e) => { const nv = [...(d.templateVars || [])]; nv[i] = e.target.value; onUpdate({ templateVars: nv }); }} placeholder="e.g. {{ order_number }}" />
                    </div>
                  ))}
                  <PlatformVariableSelector onInsert={(v) => { const nv = [...(d.templateVars || [])]; const ei = nv.findIndex(x => !x); if (ei >= 0) { nv[ei] = v; onUpdate({ templateVars: nv }); } }} />
                </div>
              )}
              {/* Header URL */}
              {d.templateHeaderType && ['IMAGE', 'VIDEO', 'DOCUMENT'].includes(d.templateHeaderType) && (
                <GcsMediaUpload
                  label={`Header ${d.templateHeaderType.toLowerCase()}`}
                  accept={d.templateHeaderType === 'IMAGE' ? 'image/*' : d.templateHeaderType === 'VIDEO' ? 'video/*' : '*/*'}
                  value={d.templateHeaderUrl || ''}
                  onChange={(url) => onUpdate({ templateHeaderUrl: url })}
                />
              )}
            </>)}
          </>)}

          {/* ── Confirmation Flow extras ── */}
          {d.actionType === 'order_confirmation_flow' && d.templateName && (<>
            <div className="border-t pt-3 mt-2">
              <div className="text-xs font-bold text-slate-600 mb-2">Confirmation Flow Settings</div>
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-1 block">Entry gate mode</label>
                <select className="w-full border rounded-lg px-3 py-2 text-sm" value={d.ocEntryGateMode || 'all'} onChange={(e) => onUpdate({ ocEntryGateMode: e.target.value })}>
                  <option value="all">All orders</option>
                  <option value="tag_or_online_store">Only tagged / online store orders</option>
                </select>
              </div>
              <div className="mt-2"><label className="text-xs font-semibold text-slate-500 mb-1 block">Confirm button titles (one per line)</label><textarea className="w-full border rounded-lg px-3 py-1.5 text-sm h-16 resize-none font-mono" value={d.ocConfirmTitles || ''} onChange={(e) => onUpdate({ ocConfirmTitles: e.target.value })} /></div>
              <div className="mt-2"><label className="text-xs font-semibold text-slate-500 mb-1 block">Change button titles (one per line)</label><textarea className="w-full border rounded-lg px-3 py-1.5 text-sm h-16 resize-none font-mono" value={d.ocChangeTitles || ''} onChange={(e) => onUpdate({ ocChangeTitles: e.target.value })} /></div>
              <div className="mt-2"><label className="text-xs font-semibold text-slate-500 mb-1 block">Talk button titles (one per line)</label><textarea className="w-full border rounded-lg px-3 py-1.5 text-sm h-16 resize-none font-mono" value={d.ocTalkTitles || ''} onChange={(e) => onUpdate({ ocTalkTitles: e.target.value })} /></div>
              <div className="mt-2"><label className="text-xs font-semibold text-slate-500 mb-1 block">Confirm audio URL</label><input className="w-full border rounded-lg px-3 py-1.5 text-sm" value={d.ocConfirmAudioUrl || ''} onChange={(e) => onUpdate({ ocConfirmAudioUrl: e.target.value })} placeholder="https://…" /></div>
              <div className="mt-2"><label className="text-xs font-semibold text-slate-500 mb-1 block">Change audio URL</label><input className="w-full border rounded-lg px-3 py-1.5 text-sm" value={d.ocChangeAudioUrl || ''} onChange={(e) => onUpdate({ ocChangeAudioUrl: e.target.value })} placeholder="https://…" /></div>
              <div className="mt-2"><label className="text-xs font-semibold text-slate-500 mb-1 block">Talk audio URL</label><input className="w-full border rounded-lg px-3 py-1.5 text-sm" value={d.ocTalkAudioUrl || ''} onChange={(e) => onUpdate({ ocTalkAudioUrl: e.target.value })} placeholder="https://…" /></div>
              <div className="mt-2 flex items-center gap-3">
                <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={d.ocSendItems !== false} onChange={(e) => onUpdate({ ocSendItems: e.target.checked })} /> Send order items</label>
                {d.ocSendItems !== false && (<div className="flex items-center gap-2"><span className="text-xs text-slate-500">Max items</span><input type="number" className="w-16 border rounded px-2 py-1 text-sm" value={d.ocMaxItems || 10} min={1} max={30} onChange={(e) => onUpdate({ ocMaxItems: Number(e.target.value) || 10 })} /></div>)}
              </div>
            </div>
          </>)}

          {/* ── Buttons ── */}
          {d.actionType === 'send_buttons' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Body text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none" value={d.buttonsText || ''} onChange={(e) => onUpdate({ buttonsText: e.target.value, description: 'Buttons: ' + e.target.value.slice(0, 30) })} placeholder="Message body…" />
              <div className="flex justify-end mt-1 mb-2"><button type="button" className="text-xl opacity-70 hover:opacity-100" onClick={() => onUpdate({ _showEmojiBtn: !d._showEmojiBtn })}>😀</button></div>
              {d._showEmojiBtn && (<div className="mb-3 border rounded-xl overflow-hidden shadow-sm"><EmojiPicker width="100%" height={300} onEmojiClick={(ev) => onUpdate({ buttonsText: (d.buttonsText || '') + ev.emoji })} /></div>)}
              <PlatformVariableSelector onInsert={(v) => onUpdate({ buttonsText: (d.buttonsText || '') + v })} />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Buttons (id|title per line)</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none font-mono" value={d.buttonsLines || ''} onChange={(e) => onUpdate({ buttonsLines: e.target.value })} placeholder={"confirm|Confirm ✅\nchange|Change order\ntalk|Talk to agent"} />
            </div>
          </>)}

          {/* ── List ── */}
          {d.actionType === 'send_list' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Body text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none" value={d.listText || ''} onChange={(e) => onUpdate({ listText: e.target.value, description: 'List: ' + e.target.value.slice(0, 30) })} placeholder="Message body…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ listText: (d.listText || '') + v })} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Button text</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.listButtonText || 'Choose'} onChange={(e) => onUpdate({ listButtonText: e.target.value })} /></div>
              <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Section title</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.listSectionTitle || ''} onChange={(e) => onUpdate({ listSectionTitle: e.target.value })} placeholder="Options" /></div>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Rows (id|title|description per line)</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-24 resize-none font-mono" value={d.listRowsLines || ''} onChange={(e) => onUpdate({ listRowsLines: e.target.value })} placeholder={"opt_1|Option One|Description\nopt_2|Option Two"} />
            </div>
          </>)}

          {/* ── Image ── */}
          {d.actionType === 'send_image' && (<>
            <GcsMediaUpload
              label="Image"
              accept="image/*"
              value={d.imageUrl || ''}
              onChange={(url) => onUpdate({ imageUrl: url, description: 'Image' })}
            />
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.caption || ''} onChange={(e) => onUpdate({ caption: e.target.value })} />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ caption: (d.caption || '') + v })} />
            </div>
          </>)}

          {/* ── Video ── */}
          {d.actionType === 'send_video' && (<>
            <GcsMediaUpload
              label="Video"
              accept="video/*"
              value={d.videoUrl || ''}
              onChange={(url) => onUpdate({ videoUrl: url, description: 'Video' })}
            />
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.caption || ''} onChange={(e) => onUpdate({ caption: e.target.value })} />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ caption: (d.caption || '') + v })} />
            </div>
          </>)}

          {/* ── Audio ── */}
          {d.actionType === 'send_audio' && (
            <GcsMediaUpload
              label="Audio"
              accept="audio/*,.ogg,.m4a,.opus"
              value={d.audioUrl || ''}
              onChange={(url) => onUpdate({ audioUrl: url, description: 'Audio' })}
            />
          )}

          {/* ── Tag / Remove Tag ── */}
          {(d.actionType === 'shopify_tag' || d.actionType === 'shopify_remove_tag') && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">{d.actionType === 'shopify_remove_tag' ? 'Tag to remove' : 'Tag to add'}</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.tag || ''} onChange={(e) => onUpdate({ tag: e.target.value, description: `Tag: ${e.target.value}` })} placeholder="e.g. VIP, confirmed" /></div>
          )}

          {/* ── Order Status Lookup ── */}
          {d.actionType === 'shopify_order_status' && (
            <div className="p-3 rounded-lg bg-sky-50 border border-sky-200 text-sm text-sky-700">
              <div className="font-semibold mb-1">Order Status Lookup</div>
              <div className="text-xs">Automatically looks up the customer's latest orders from Shopify and sends the status in Arabic. No configuration needed.</div>
            </div>
          )}

          {/* ── Catalog Item ── */}
          {d.actionType === 'send_catalog_item' && (<>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Product retailer ID</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.catalogItemRetailerId || ''} onChange={(e) => onUpdate({ catalogItemRetailerId: e.target.value, description: `Catalog: ${e.target.value}` })} placeholder="e.g. SKU-001" /></div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.catalogItemCaption || ''} onChange={(e) => onUpdate({ catalogItemCaption: e.target.value })} placeholder="Product description…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ catalogItemCaption: (d.catalogItemCaption || '') + v })} />
            </div>
          </>)}

          {/* ── Catalog Set ── */}
          {d.actionType === 'send_catalog_set' && (<>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Catalog set ID</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.catalogSetId || ''} onChange={(e) => onUpdate({ catalogSetId: e.target.value, description: `Set: ${e.target.value}` })} placeholder="e.g. summer_2024" /></div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.catalogSetCaption || ''} onChange={(e) => onUpdate({ catalogSetCaption: e.target.value })} placeholder="Collection description…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ catalogSetCaption: (d.catalogSetCaption || '') + v })} />
            </div>
          </>)}

          {/* ── Last Order Items ── */}
          {d.actionType === 'send_last_order_catalog_items' && (<>
            <div className="p-3 rounded-lg bg-pink-50 border border-pink-200 text-sm text-pink-700">
              <div className="font-semibold mb-1">Last Order Catalog Items</div>
              <div className="text-xs">Sends the customer's last order items as interactive catalog product cards. You can add an Audio node below to send a voice note alongside.</div>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Max items to send</label>
              <input type="number" className="w-full border rounded-lg px-3 py-2 text-sm" value={d.lastOrderItemsMax || 10} min={1} max={30} onChange={(e) => onUpdate({ lastOrderItemsMax: Number(e.target.value) || 10 })} />
            </div>
          </>)}

          {/* ── Assign Agent ── */}
          {d.actionType === 'assign_agent' && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Agent name</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.agent || ''} onChange={(e) => onUpdate({ agent: e.target.value, description: `Assign: ${e.target.value}` })} placeholder="e.g. support-team" /></div>
          )}

          {/* ── Close / Exit ── */}
          {d.actionType === 'close_conversation' && (
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-600">Marks the conversation as resolved. No config needed.</div>
          )}
          {d.actionType === 'exit' && (
            <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-sm text-rose-600">Stops the workflow here. No further actions will execute.</div>
          )}
        </>)}

        {t === 'delayFlow' && (
          <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Wait (minutes)</label><input type="number" className="w-full border rounded-lg px-3 py-2 text-sm" value={d.minutes || 10} min={1} onChange={(e) => onUpdate({ minutes: Math.max(1, Number(e.target.value) || 1) })} /></div>
        )}

        {/* ── Button Reply node editor ── */}
        {t === 'buttonReply' && (<>
          <div className="p-3 rounded-lg bg-indigo-50 border border-indigo-200">
            <div className="text-xs font-bold text-indigo-700 mb-1">When customer clicks</div>
            <div className="text-sm font-semibold text-slate-800">"{d.buttonText || 'Button'}"</div>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 mb-1 block">Reply action</label>
            <select
              className="w-full border rounded-lg px-3 py-2 text-sm bg-white"
              value={d.replyActionType || ''}
              onChange={(e) => {
                const cat = ACTION_CATALOG.find(a => a.type === e.target.value);
                onUpdate({ replyActionType: e.target.value, replyActionLabel: cat?.label || e.target.value });
              }}
            >
              <option value="">-- No reply action --</option>
              {ACTION_CATEGORIES.map(cat => {
                const items = ACTION_CATALOG.filter(a => a.cat === cat.id);
                return (<optgroup key={cat.id} label={cat.label}>{items.map(a => (<option key={a.id} value={a.type}>{a.label}</option>))}</optgroup>);
              })}
            </select>
          </div>
          {/* ── Send Text ── */}
          {d.replyActionType === 'send_whatsapp_text' && (
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Reply message</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-24 resize-none" value={d.replyText || ''} onChange={(e) => onUpdate({ replyText: e.target.value })} placeholder="Message to send when this button is clicked…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyText: (d.replyText || '') + v })} />
            </div>
          )}
          {/* ── Send Template ── */}
          {d.replyActionType === 'send_whatsapp_template' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Reply template</label>
              <select className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyTemplateName || ''} onChange={(e) => {
                const tn = e.target.value;
                const tpl = (templates || []).find(t2 => t2.name === tn);
                const lang = tpl?.language || 'en';
                const varNames = _inferBodyVarNamesFromTpl(tpl);
                const tplVars = varNames.map(() => '');
                onUpdate({ replyTemplateName: tn, replyTemplateLanguage: lang, replyTemplateVars: tplVars });
              }}>
                <option value="">Select a template…</option>
                {(templates || []).filter(tp => String(tp.status || '').toLowerCase() === 'approved').map(tp => (
                  <option key={tp.name + '_' + tp.language} value={tp.name}>{tp.name} ({tp.language})</option>
                ))}
              </select>
            </div>
            {d.replyTemplateName && (d.replyTemplateVars || []).length > 0 && (
              <div>
                <label className="text-xs font-semibold text-slate-500 mb-2 block">Body Variables ({(d.replyTemplateVars || []).length})</label>
                {(d.replyTemplateVars || []).map((v, i) => (
                  <div key={i} className="flex items-center gap-2 mb-2">
                    <span className="text-xs text-slate-400 font-mono w-10 flex-shrink-0">{`{{${i+1}}}`}</span>
                    <input className="flex-1 border rounded-lg px-3 py-1.5 text-sm" value={v} onChange={(e) => { const nv = [...(d.replyTemplateVars || [])]; nv[i] = e.target.value; onUpdate({ replyTemplateVars: nv }); }} placeholder="e.g. {{ order_number }}" />
                  </div>
                ))}
                <PlatformVariableSelector onInsert={(v) => { const nv = [...(d.replyTemplateVars || [])]; const ei = nv.findIndex(x => !x); if (ei >= 0) { nv[ei] = v; onUpdate({ replyTemplateVars: nv }); } }} />
              </div>
            )}
          </>)}
          {/* ── Send Catalog Set ── */}
          {d.replyActionType === 'send_catalog_set' && (<>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Catalog set ID</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyCatalogSetId || ''} onChange={(e) => onUpdate({ replyCatalogSetId: e.target.value })} placeholder="e.g. summer_2024" /></div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.replyCatalogSetCaption || ''} onChange={(e) => onUpdate({ replyCatalogSetCaption: e.target.value })} placeholder="Collection description…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyCatalogSetCaption: (d.replyCatalogSetCaption || '') + v })} />
            </div>
          </>)}
          {/* ── Send Catalog Item ── */}
          {d.replyActionType === 'send_catalog_item' && (<>
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Product retailer ID</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyCatalogItemRetailerId || ''} onChange={(e) => onUpdate({ replyCatalogItemRetailerId: e.target.value })} placeholder="e.g. SKU-001" /></div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.replyCatalogItemCaption || ''} onChange={(e) => onUpdate({ replyCatalogItemCaption: e.target.value })} placeholder="Product description…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyCatalogItemCaption: (d.replyCatalogItemCaption || '') + v })} />
            </div>
          </>)}
          {/* ── Send Audio ── */}
          {d.replyActionType === 'send_audio' && (
            <GcsMediaUpload label="Audio" accept="audio/*,.ogg,.m4a,.opus" value={d.replyAudioUrl || ''} onChange={(url) => onUpdate({ replyAudioUrl: url })} />
          )}
          {/* ── Send Image ── */}
          {d.replyActionType === 'send_image' && (<>
            <GcsMediaUpload label="Image" accept="image/*" value={d.replyImageUrl || ''} onChange={(url) => onUpdate({ replyImageUrl: url })} />
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.replyImageCaption || ''} onChange={(e) => onUpdate({ replyImageCaption: e.target.value })} />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyImageCaption: (d.replyImageCaption || '') + v })} />
            </div>
          </>)}
          {/* ── Send Video ── */}
          {d.replyActionType === 'send_video' && (<>
            <GcsMediaUpload label="Video" accept="video/*" value={d.replyVideoUrl || ''} onChange={(url) => onUpdate({ replyVideoUrl: url })} />
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Caption</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-16 resize-none" value={d.replyVideoCaption || ''} onChange={(e) => onUpdate({ replyVideoCaption: e.target.value })} />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyVideoCaption: (d.replyVideoCaption || '') + v })} />
            </div>
          </>)}
          {/* ── Send List ── */}
          {d.replyActionType === 'send_list' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Body text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none" value={d.replyListText || ''} onChange={(e) => onUpdate({ replyListText: e.target.value })} placeholder="Message body…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyListText: (d.replyListText || '') + v })} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Button text</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyListButtonText || 'Choose'} onChange={(e) => onUpdate({ replyListButtonText: e.target.value })} /></div>
              <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Section title</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyListSectionTitle || ''} onChange={(e) => onUpdate({ replyListSectionTitle: e.target.value })} placeholder="Options" /></div>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Rows (id|title|description per line)</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-24 resize-none font-mono" value={d.replyListRowsLines || ''} onChange={(e) => onUpdate({ replyListRowsLines: e.target.value })} placeholder={"opt_1|Option One|Description\nopt_2|Option Two"} />
            </div>
          </>)}
          {/* ── Send Buttons ── */}
          {d.replyActionType === 'send_buttons' && (<>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Body text</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none" value={d.replyButtonsText || ''} onChange={(e) => onUpdate({ replyButtonsText: e.target.value })} placeholder="Message body…" />
              <PlatformVariableSelector onInsert={(v) => onUpdate({ replyButtonsText: (d.replyButtonsText || '') + v })} />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Buttons (id|title per line)</label>
              <textarea className="w-full border rounded-lg px-3 py-2 text-sm h-20 resize-none font-mono" value={d.replyButtonsLines || ''} onChange={(e) => onUpdate({ replyButtonsLines: e.target.value })} placeholder={"confirm|Confirm ✅\nchange|Change order"} />
            </div>
          </>)}
          {/* ── Last Order Items ── */}
          {d.replyActionType === 'send_last_order_catalog_items' && (<>
            <div className="p-3 rounded-lg bg-pink-50 border border-pink-200 text-sm text-pink-700">
              <div className="font-semibold mb-1">Last Order Catalog Items</div>
              <div className="text-xs">Sends the customer's last order items as catalog cards.</div>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 mb-1 block">Max items to send</label>
              <input type="number" className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyLastOrderItemsMax || 10} min={1} max={30} onChange={(e) => onUpdate({ replyLastOrderItemsMax: Number(e.target.value) || 10 })} />
            </div>
          </>)}
          {/* ── Order Status Lookup ── */}
          {d.replyActionType === 'shopify_order_status' && (
            <div className="p-3 rounded-lg bg-sky-50 border border-sky-200 text-sm text-sky-700">
              <div className="font-semibold mb-1">Order Status Lookup</div>
              <div className="text-xs">Automatically looks up the customer's latest orders and sends the status. No configuration needed.</div>
            </div>
          )}
          {/* ── Tag / Remove Tag ── */}
          {(d.replyActionType === 'shopify_tag' || d.replyActionType === 'shopify_remove_tag') && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">{d.replyActionType === 'shopify_remove_tag' ? 'Tag to remove' : 'Tag to add'}</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyTag || ''} onChange={(e) => onUpdate({ replyTag: e.target.value })} placeholder="e.g. VIP, confirmed" /></div>
          )}
          {/* ── Order Confirmation Flow ── */}
          {d.replyActionType === 'order_confirmation_flow' && (
            <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-sm text-emerald-700">
              <div className="font-semibold mb-1">Confirmation Flow</div>
              <div className="text-xs">Multi-step order confirmation with buttons. Configure this as a top-level action for full control.</div>
            </div>
          )}
          {/* ── Close / Exit / Assign ── */}
          {d.replyActionType === 'close_conversation' && (
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-600">Marks conversation as resolved.</div>
          )}
          {d.replyActionType === 'assign_agent' && (
            <div><label className="text-xs font-semibold text-slate-500 mb-1 block">Agent name</label><input className="w-full border rounded-lg px-3 py-2 text-sm" value={d.replyAgent || ''} onChange={(e) => onUpdate({ replyAgent: e.target.value })} placeholder="e.g. support-team" /></div>
          )}
          {d.replyActionType === 'exit' && (
            <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-sm text-rose-600">Stops the workflow for this button branch.</div>
          )}
        </>)}

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
  const [stats, setStats] = useState({}); // per-rule stats from /automation/rules/stats
  const [editingRuleId, setEditingRuleId] = useState(null); // rule id being edited

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

  const loadStats = useCallback(async () => {
    try {
      const res = await api.get('/automation/rules/stats');
      setStats((res?.data?.stats && typeof res.data.stats === 'object') ? res.data.stats : {});
    } catch {
      setStats({});
    }
  }, []);

  useEffect(() => {
    loadRules();
    loadTemplates();
    loadStats();
  }, [loadRules, loadTemplates, loadStats]);

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

      if (at === 'delay') {
        nodes.push(rfNode(aId, 'delayFlow', 0, yPos, { minutes: a.minutes || 10 }));
      } else {
        // Map rule action type → flow actionType + label + data
        let actionType = 'send_whatsapp_text';
        let label = 'Send Text';
        const extra = {};
        if (at.includes('template') && !at.includes('confirmation') && !at.includes('order')) {
          actionType = 'send_whatsapp_template'; label = 'Send Template';
          extra.templateName = a.template_name || '';
          extra.templateLanguage = a.language || 'en';
          // Restore template vars from components
          const bodyComp = (a.components || []).find(c => c?.type === 'body');
          extra.templateVars = (bodyComp?.parameters || []).map(p => p?.text || '');
          const headerComp = (a.components || []).find(c => c?.type === 'header');
          if (headerComp?.parameters?.[0]) {
            const hp = headerComp.parameters[0];
            if (hp.image) { extra.templateHeaderType = 'IMAGE'; extra.templateHeaderUrl = hp.image.link || ''; }
            else if (hp.video) { extra.templateHeaderType = 'VIDEO'; extra.templateHeaderUrl = hp.video.link || ''; }
            else if (hp.document) { extra.templateHeaderType = 'DOCUMENT'; extra.templateHeaderUrl = hp.document.link || ''; }
          }
        } else if (at === 'order_confirmation_flow') {
          actionType = 'order_confirmation_flow'; label = 'Confirmation Flow';
          extra.templateName = a.template_name || '';
          extra.templateLanguage = a.language || 'en';
          const bodyComp = (a.components || []).find(c => c?.type === 'body');
          extra.templateVars = (bodyComp?.parameters || []).map(p => p?.text || '');
          extra.ocEntryGateMode = a.entry_gate_mode || 'all';
          extra.ocConfirmTitles = (a.confirm_titles || []).join('\n');
          extra.ocChangeTitles = (a.change_titles || []).join('\n');
          extra.ocTalkTitles = (a.talk_titles || []).join('\n');
          extra.ocConfirmAudioUrl = a.confirm_audio_url || '';
          extra.ocChangeAudioUrl = a.change_audio_url || '';
          extra.ocTalkAudioUrl = a.talk_audio_url || '';
          extra.ocSendItems = a.send_items !== false;
          extra.ocMaxItems = a.max_items || 10;
        } else if (at === 'send_buttons') {
          actionType = 'send_buttons'; label = 'Send Buttons';
          extra.buttonsText = a.text || '';
          extra.buttonsLines = (a.buttons || []).map(b => `${b.id}|${b.title}`).join('\n');
        } else if (at === 'send_list') {
          actionType = 'send_list'; label = 'Send List';
          extra.listText = a.text || '';
          extra.listButtonText = a.button_text || 'Choose';
          const sec = (a.sections || [])[0] || {};
          extra.listSectionTitle = sec.title || '';
          extra.listRowsLines = (sec.rows || []).map(r => `${r.id}|${r.title}${r.description ? '|' + r.description : ''}`).join('\n');
        } else if (at === 'send_image') {
          actionType = 'send_image'; label = 'Send Image';
          extra.imageUrl = a.image_url || ''; extra.caption = a.caption || '';
        } else if (at === 'send_video') {
          actionType = 'send_video'; label = 'Send Video';
          extra.videoUrl = a.video_url || ''; extra.caption = a.caption || '';
        } else if (at === 'send_audio' || at === 'send_audio_url') {
          actionType = 'send_audio'; label = 'Send Audio';
          extra.audioUrl = a.audio_url || '';
        } else if (at === 'add_tag' || (at.includes('tag') && !at.includes('remove'))) {
          actionType = 'shopify_tag'; label = 'Tag Customer';
          extra.tag = a.tag || '';
        } else if (at === 'remove_tag' || (at.includes('remove') && at.includes('tag'))) {
          actionType = 'shopify_remove_tag'; label = 'Remove Tag';
          extra.tag = a.tag || '';
        } else if (at === 'shopify_order_status') {
          actionType = 'shopify_order_status'; label = 'Order Status';
        } else if (at === 'send_catalog_item') {
          actionType = 'send_catalog_item'; label = 'Catalog Item';
          extra.catalogItemRetailerId = a.retailer_id || ''; extra.catalogItemCaption = a.caption || '';
        } else if (at === 'send_catalog_set') {
          actionType = 'send_catalog_set'; label = 'Catalog Set';
          extra.catalogSetId = a.set_id || ''; extra.catalogSetCaption = a.caption || '';
        } else if (at === 'send_last_order_catalog_items') {
          actionType = 'send_last_order_catalog_items'; label = 'Last Order Items';
          extra.lastOrderItemsMax = a.max_items || 10;
        } else if (at === 'assign_agent') {
          actionType = 'assign_agent'; label = 'Assign Agent';
          extra.agent = a.agent || '';
        } else if (at === 'close_conversation') {
          actionType = 'close_conversation'; label = 'Close';
        } else if (at === 'exit') {
          actionType = 'exit'; label = 'Stop';
        }

        const catEntry = ACTION_CATALOG.find(c => c.type === actionType);
        nodes.push(rfNode(aId, 'actionFlow', 0, yPos, {
          actionType, actionLabel: catEntry?.label || label,
          text: a.text || '',
          description: a.preview || a.text?.slice(0, 50) || a.template_name || label,
          ...extra,
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
      setEditingRuleId(null);
      setView('canvas');
    } else if (rule) {
      const flow = openRuleAsFlow(rule);
      setEditingFlow(flow);
      setEditingRuleId(rule.id || null);
      setView('canvas');
    }
  }, [openRuleAsFlow]);

  const handleNewFlow = useCallback(() => {
    setEditingFlow(newBlankFlow());
    setEditingRuleId(null);
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
          flowStats={editingRuleId ? (stats[editingRuleId] || {}) : {}}
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
      stats={stats}
    />
  );
}
