// Lightweight Automation Studio — WhatsApp × Shopify
// Self-contained, Tailwind-only (no shadcn, no framer-motion)
import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Rocket,
  Plus,
  Play,
  Save,
  CirclePlay,
  ShoppingCart,
  MessageSquare,
  Timer,
  GitBranch,
  Webhook,
  SplitSquareHorizontal,
  CheckCircle2,
  Ban,
  ScanLine,
  Settings2,
  Trash,
} from "lucide-react";
import api from "./api";
import WhatsAppTemplatesPanel from "./WhatsAppTemplatesPanel";

const NODE_TYPES = {
  TRIGGER: "trigger",
  CONDITION: "condition",
  ACTION: "action",
  DELAY: "delay",
  EXIT: "exit",
};

const PORT = { IN: "in", OUT: "out" };

const TRIGGERS = [
  {
    id: "t_shopify_paid",
    label: "Shopify: Order Paid",
    icon: <ShoppingCart className="w-4 h-4" />,
    payloadHint:
      '{"topic":"orders/paid","order_number":"#1024","total_price":499,"customer":{"phone":"+212612345678","first_name":"Nora"}}',
    config: { source: "shopify", topic: "orders/paid" },
  },
  {
    id: "t_shopify_fulfilled",
    label: "Shopify: Fulfillment Out for Delivery",
    icon: <ScanLine className="w-4 h-4" />,
    payloadHint:
      '{"topic":"fulfillments/create","tracking":"OSC123","customer":{"phone":"+212612345678"}}',
    config: { source: "shopify", topic: "fulfillments/create" },
  },
  {
    id: "t_whatsapp_in",
    label: "WhatsApp: Incoming Message",
    icon: <MessageSquare className="w-4 h-4" />,
    payloadHint: '{"text":"size 38 for girl" ,"from":"+212612345678"}',
    config: { source: "whatsapp", topic: "message" },
  },
];

const ACTIONS = [
  {
    id: "a_send_template",
    label: "WhatsApp: Send Template",
    icon: <MessageSquare className="w-4 h-4" />,
    config: {
      type: "send_whatsapp_template",
      to: "{{ phone }}",
      template_name: "order_confirmed",
      language: "en",
      components: [
        { type: "body", parameters: [{ type: "text", text: "{{ order_number }}" }] },
      ],
    },
  },
  {
    id: "a_send_text",
    label: "WhatsApp: Send Text",
    icon: <MessageSquare className="w-4 h-4" />,
    config: {
      type: "send_whatsapp_text",
      to: "{{ phone }}",
      text: "مرحبا! طلبك قيد المعالجة.",
    },
  },
  {
    id: "a_stop",
    label: "Stop / Exit",
    icon: <Ban className="w-4 h-4" />,
    config: { type: "exit" },
  },
];

const LOGIC = [
  {
    id: "c_condition",
    label: "Condition",
    icon: <SplitSquareHorizontal className="w-4 h-4" />,
    config: {
      expression: "{{ topic }} == 'orders/paid' && {{ total_price }} >= 300",
      trueLabel: "Yes",
      falseLabel: "No",
    },
  },
  {
    id: "d_delay",
    label: "Delay",
    icon: <Timer className="w-4 h-4" />,
    config: { minutes: 10 },
  },
];

// Shopify event catalog with common variables and sample payload hints
const SHOPIFY_EVENTS = [
  {
    id: "draft_orders/create",
    label: "Shopify: Draft Order Created",
    topic: "draft_orders/create",
    variables: [
      "id",
      "name",
      "invoice_url",
      "status",
      "note",
      "tags",
      "total_price",
      "created_at",
      "customer.id",
      "customer.first_name",
      "customer.last_name",
      "customer.phone",
      "shipping_address.city",
      "shipping_address.province",
    ],
    sample: JSON.stringify({
      topic: "draft_orders/create",
      id: 777,
      name: "#D1025",
      status: "open",
      note: "Test note",
      tags: "test, vip",
      total_price: 199,
      created_at: "2024-01-01T12:00:00Z",
      customer: { id: 999, first_name: "Nora", last_name: "A.", phone: "+212612345678" },
      shipping_address: { city: "Casablanca", province: "Casablanca-Settat" },
    }, null, 2),
  },
  {
    id: "orders/create",
    label: "Shopify: New Order",
    topic: "orders/create",
    variables: [
      "id",
      "order_number",
      "financial_status",
      "total_price",
      "created_at",
      "customer.id",
      "customer.first_name",
      "customer.last_name",
      "customer.phone",
      "line_items[].title",
      "line_items[].variant_title",
      "shipping_address.city",
      "shipping_address.province",
    ],
    sample: JSON.stringify({
      topic: "orders/create",
      id: 123456,
      order_number: "#1025",
      financial_status: "paid",
      total_price: 499,
      created_at: "2024-01-01T12:00:00Z",
      customer: { id: 999, first_name: "Nora", last_name: "A.", phone: "+212612345678" },
      line_items: [{ title: "T-Shirt", variant_title: "Large" }],
      shipping_address: { city: "Casablanca", province: "Casablanca-Settat" },
    }, null, 2),
  },
  {
    id: "orders/paid",
    label: "Shopify: Order Paid",
    topic: "orders/paid",
    variables: ["id", "order_number", "total_price", "customer.phone", "created_at"],
    sample: JSON.stringify({
      topic: "orders/paid",
      id: 123456,
      order_number: "#1025",
      total_price: 499,
      created_at: "2024-01-01T12:00:00Z",
      customer: { phone: "+212612345678" },
    }, null, 2),
  },
  {
    id: "customers/create",
    label: "Shopify: New Customer",
    topic: "customers/create",
    variables: [
      "id",
      "email",
      "first_name",
      "last_name",
      "phone",
      "default_address.city",
      "default_address.province",
    ],
    sample: JSON.stringify({
      topic: "customers/create",
      id: 1001,
      email: "nora@example.com",
      first_name: "Nora",
      last_name: "A.",
      phone: "+212612345678",
      default_address: { city: "Rabat", province: "Rabat-Salé-Kénitra" },
    }, null, 2),
  },
  {
    id: "checkouts/update",
    label: "Shopify: Abandoned Checkout",
    topic: "checkouts/update",
    variables: [
      "id",
      "abandoned_checkout_url",
      "email",
      "phone",
      "line_items[].title",
      "line_items[].variant_title",
      "total_price",
      "created_at",
    ],
    sample: JSON.stringify({
      topic: "checkouts/update",
      id: 222,
      abandoned_checkout_url: "https://shop.myshopify.com/123/abandon",
      email: "nora@example.com",
      phone: "+212612345678",
      line_items: [{ title: "Shoes", variant_title: "42" }],
      total_price: 299,
      created_at: "2024-01-01T12:10:00Z",
    }, null, 2),
  },
];

const DELIVERY_VARS = [
  "status",
  "order_id",
  "order_name",
  "city",
  "cash_amount",
  "phone",
  "order.customer_phone",
  "order.address",
  "order.tags",
  "payload",
];

// Default branch titles (used as initial placeholders; UI can auto-fill from template buttons)
const DEFAULT_OC_CONFIRM_TITLES = "تأكيد الطلب\nتاكيد الطلب";
const DEFAULT_OC_CHANGE_TITLES = "تغيير المعلومات\nتغير المعلومات";
const DEFAULT_OC_TALK_TITLES = "تكلم مع العميل";

function TagIcon() {
  return (
    <svg
      className="w-4 h-4"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M20.59 13.41 11 3H4v7l9.59 9.59a2 2 0 0 0 2.82 0l4.18-4.18a2 2 0 0 0 0-2.82Z" />
      <path d="M7 7h.01" />
    </svg>
  );
}

let idSeq = 1;
const nextId = () => "n" + idSeq++;

const defaultFlow = () => {
  const trigger = makeNode(NODE_TYPES.TRIGGER, 120, 160, {
    name: "Order Paid",
    ...TRIGGERS[0].config,
    sample: TRIGGERS[0].payloadHint,
  });
  const cond = makeNode(NODE_TYPES.CONDITION, 420, 160, {
    expression: "{{ total_price }} >= 300",
    trueLabel: "VIP",
    falseLabel: "Regular",
  });
  const act1 = makeNode(NODE_TYPES.ACTION, 720, 80, {
    label: "Send Confirm (EN)",
    ...ACTIONS[0].config,
  });
  const delay = makeNode(NODE_TYPES.DELAY, 720, 240, { minutes: 5 });
  const act2 = makeNode(NODE_TYPES.ACTION, 960, 240, {
    label: "Nurture Text (AR)",
    ...ACTIONS[1].config,
    text: "مبروك 🎉 الطلب ديالك تأكد. شكراً على الثقة!",
  });

  const edges = [
    makeEdge(trigger.id, PORT.OUT, cond.id, PORT.IN),
    makeEdge(cond.id, "true", act1.id, PORT.IN),
    makeEdge(cond.id, "false", delay.id, PORT.IN),
    makeEdge(delay.id, PORT.OUT, act2.id, PORT.IN),
  ];

  return { nodes: [trigger, cond, act1, delay, act2], edges };
};

function makeNode(type, x, y, data = {}) {
  return { id: nextId(), type, x, y, data, selected: false };
}

function makeEdge(from, fromPort, to, toPort) {
  return { id: nextId(), from, fromPort, to, toPort };
}

export default function AutomationStudio({ onClose }) {
  // Simple mode: real rules persisted in backend and executed on inbound WhatsApp messages.
  // Settings are now in a dedicated page (/#/automation-settings).
  const [mode, setMode] = useState("simple"); // simple | templates | (legacy flow editor)
  const [rules, setRules] = useState([]);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [rulesSaving, setRulesSaving] = useState(false);
  const [rulesError, setRulesError] = useState("");
  const [ruleStats, setRuleStats] = useState({});
  const [editorOpen, setEditorOpen] = useState(false);
  const [workspaceOptions, setWorkspaceOptions] = useState([]);
  const [deliveryStatusOptions, setDeliveryStatusOptions] = useState([]);

  const currentWorkspace = (() => {
    try { return (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova'; } catch { return 'irranova'; }
  })();

  const [draft, setDraft] = useState({
    id: "",
    name: "",
    enabled: true,
    workspaceScope: "current", // 'current' | 'all' | 'selected'
    workspaces: [],
    keywords: "",
    replyText: "",
    tag: "",
    cooldownSeconds: 0,
    triggerSource: "whatsapp",
    waTriggerMode: "incoming", // incoming | no_reply | button
    noReplyMinutes: 30,
    whatsappTestPhones: "",
    waNoUrlNoDigit: false,
    buttonIds: "",
    shopifyTopic: "orders/paid",
    shopifyTaggedWith: "",
    shopifyTestPhones: "",
    shopifyTagOnSent: "",
    deliveryStatuses: "",
    deliveryTestPhones: "",
    actionMode: "text", // 'text' | 'template' | 'order_confirm' | 'buttons' | 'list' | 'order_status'
    to: "{{ phone }}",
    templateName: "",
    templateLanguage: "en",
    templateVars: [],
    templateHeaderUrl: "",
    // Buttons action
    buttonsText: "",
    buttonsLines: "buy_item|Acheter | شراء\norder_status|Statut | حالة",
    // List action
    listText: "",
    listButtonText: "Choisir | اختر",
    listSectionTitle: "Options",
    listRowsLines: "gender_girls|Fille | بنت\ngender_boys|Garçon | ولد",
    // Order confirmation flow (multi-step)
    ocConfirmTitles: "تأكيد الطلب\nتاكيد الطلب",
    ocChangeTitles: "تغيير المعلومات\nتغير المعلومات",
    ocTalkTitles: "تكلم مع العميل",
    ocConfirmIds: "",
    ocChangeIds: "",
    ocTalkIds: "",
    ocConfirmAudioUrl: "",
    ocChangeAudioUrl: "",
    ocTalkAudioUrl: "",
    ocSendItems: true,
    ocMaxItems: 10,
  });

  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [templatesError, setTemplatesError] = useState("");
  const [templates, setTemplates] = useState([]);

  const loadRules = async () => {
    setRulesError("");
    setRulesLoading(true);
    try {
      const res = await api.get("/automation/rules");
      const arr = Array.isArray(res?.data) ? res.data : [];
      setRules(arr);
    } catch (e) {
      setRulesError("Failed to load automations (admin only).");
      setRules([]);
    } finally {
      setRulesLoading(false);
    }
  };

  const persistRules = async (nextRules) => {
    setRulesError("");
    setRulesSaving(true);
    try {
      await api.post("/automation/rules", { rules: nextRules });
      setRules(nextRules);
    } catch (e) {
      setRulesError("Failed to save automations.");
    } finally {
      setRulesSaving(false);
    }
  };

  const loadRuleStats = async () => {
    try {
      const res = await api.get("/automation/rules/stats");
      const s = res?.data?.stats || {};
      setRuleStats(s && typeof s === "object" ? s : {});
    } catch {
      setRuleStats({});
    }
  };

  const loadTemplates = async () => {
    setTemplatesError("");
    setTemplatesLoading(true);
    try {
      const res = await api.get("/admin/whatsapp/templates");
      const arr = Array.isArray(res?.data?.templates) ? res.data.templates : [];
      setTemplates(arr);
    } catch (e) {
      setTemplatesError("Failed to load WhatsApp templates. Check WABA ID + permissions.");
      setTemplates([]);
    } finally {
      setTemplatesLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
    loadRuleStats();
    // Templates are optional; don't block page load if not configured.
    loadTemplates();
    // Load available workspaces for per-rule scoping UI (best-effort).
    (async () => {
      try {
        const res = await api.get('/app-config');
        const list = Array.isArray(res?.data?.workspaces) ? res.data.workspaces : [];
        const norm = list
          .map((w) => ({
            id: String(w?.id || '').trim().toLowerCase(),
            label: String(w?.label || '').trim(),
          }))
          .filter((w) => w.id);
        setWorkspaceOptions(norm);
        const ds = Array.isArray(res?.data?.delivery_statuses) ? res.data.delivery_statuses : [];
        setDeliveryStatusOptions(ds.map((x) => String(x || "").trim()).filter(Boolean));
      } catch {
        setWorkspaceOptions([]);
        setDeliveryStatusOptions([]);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [flow, setFlow] = useState(defaultFlow);
  const [linking, setLinking] = useState(null);
  const [selected, setSelected] = useState(null);
  const [zoom, setZoom] = useState(1);

  const dragRef = useRef({ id: null, offsetX: 0, offsetY: 0 });
  const canvasRef = useRef(null);

  const onCanvasDown = (e) => {
    if (e.target.dataset && e.target.dataset.canvas) {
      setSelected(null);
    }
  };

  const onNodeMouseDown = (e, node) => {
    const rect = e.currentTarget.getBoundingClientRect();
    dragRef.current = {
      id: node.id,
      offsetX: e.clientX - rect.left,
      offsetY: e.clientY - rect.top,
    };
    setSelected(node.id);
  };

  const onMouseMove = (e) => {
    const d = dragRef.current;
    if (!d.id) return;
    const rect = canvasRef.current ? canvasRef.current.getBoundingClientRect() : null;
    if (!rect) return;
    setFlow((f) => ({
      ...f,
      nodes: f.nodes.map((n) =>
        n.id === d.id
          ? {
              ...n,
              x: (e.clientX - rect.left - d.offsetX) / zoom,
              y: (e.clientY - rect.top - d.offsetY) / zoom,
            }
          : n
      ),
    }));
  };

  const onMouseUp = () => {
    dragRef.current = { id: null };
  };

  const startLink = (nodeId, port) => setLinking({ from: nodeId, fromPort: port });
  const completeLink = (toId, toPort) => {
    if (!linking) return;
    if (linking.from === toId) return setLinking(null);
    setFlow((f) => ({
      ...f,
      edges: [...f.edges, makeEdge(linking.from, linking.fromPort, toId, toPort)],
    }));
    setLinking(null);
  };

  const deleteNode = (id) =>
    setFlow((f) => ({
      nodes: f.nodes.filter((n) => n.id !== id),
      edges: f.edges.filter((e) => e.from !== id && e.to !== id),
    }));

  const deleteEdge = (id) =>
    setFlow((f) => ({ ...f, edges: f.edges.filter((e) => e.id !== id) }));

  const addNode = (preset) => {
    let type = NODE_TYPES.ACTION;
    if (TRIGGERS.find((t) => t.id === preset.id)) type = NODE_TYPES.TRIGGER;
    if (LOGIC.find((l) => l.id === preset.id || preset.id?.startsWith("c_")))
      type = NODE_TYPES.CONDITION;
    if (preset.id?.startsWith("d_")) type = NODE_TYPES.DELAY;

    const x = 240 + Math.random() * 400;
    const y = 140 + Math.random() * 260;
    const data = { ...preset.config };
    if (preset.payloadHint) data.sample = preset.payloadHint;
    setFlow((f) => ({ ...f, nodes: [...f.nodes, makeNode(type, x, y, data)] }));
  };

  const selectedNode = flow.nodes.find((n) => n.id === selected) || null;

  const onUpdateSelected = (patch) => {
    if (!selectedNode) return;
    setFlow((f) => ({
      ...f,
      nodes: f.nodes.map((n) =>
        n.id === selectedNode.id ? { ...n, data: { ...n.data, ...patch } } : n
      ),
    }));
  };

  const [running, setRunning] = useState(false);
  const [activeNodeId, setActiveNodeId] = useState(null);

  const simulate = async () => {
    setRunning(true);
    const triggers = flow.nodes.filter((n) => n.type === NODE_TYPES.TRIGGER);
    if (!triggers.length) {
      setRunning(false);
      return;
    }
    for (const start of triggers) {
      // eslint-disable-next-line no-await-in-loop
      await visit(start.id);
    }
    setRunning(false);
  };

  const visit = async (nodeId) => {
    setActiveNodeId(nodeId);
    await wait(600);
    const node = flow.nodes.find((n) => n.id === nodeId);
    if (!node) return;
    const outs = flow.edges.filter((e) => e.from === nodeId);
    if (node.type === NODE_TYPES.CONDITION) {
      const yes = outs.find((e) => e.fromPort === "true");
      const no = outs.find((e) => e.fromPort === "false");
      const next = Math.random() > 0.5 ? yes : no;
      if (next) await visit(next.to);
      return;
    }
    for (const edge of outs) {
      // eslint-disable-next-line no-await-in-loop
      await visit(edge.to);
    }
  };

  const wait = (ms) => new Promise((res) => setTimeout(res, ms));

  return (
    <div className="h-screen w-full bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-sky-50 via-white to-indigo-50 text-slate-800">
      <header className="h-12 px-3 flex items-center justify-between border-b bg-white/70 backdrop-blur sticky top-0 z-50">
        <div className="flex items-center gap-2">
          <Rocket className="w-5 h-5 text-blue-600" />
          <h1 className="font-semibold text-base">Automation Studio — WhatsApp × Shopify</h1>
          <span className="text-xs px-2 py-0.5 rounded bg-blue-100 text-blue-700">Beta</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="hidden sm:flex items-center gap-1 mr-2">
            <button
              className={`px-2 py-1 border rounded text-sm ${mode === "simple" ? "bg-blue-50 border-blue-200" : ""}`}
              onClick={() => setMode("simple")}
            >
              Automation
            </button>
            <button
              className={`px-2 py-1 border rounded text-sm ${mode === "templates" ? "bg-blue-50 border-blue-200" : ""}`}
              onClick={() => setMode("templates")}
            >
              WhatsApp Templates
            </button>
          </div>
          <button
            className="px-2 py-1 border rounded text-sm"
            onClick={() => { try { window.location.href = '/'; } catch {} }}
            title="Back to Inbox"
          >
            Inbox
          </button>
          <button
            className="px-2 py-1 border rounded text-sm"
            onClick={() => { try { window.location.href = '/#/analytics'; } catch {} }}
            title="Analytics"
          >
            Analytics
          </button>
          <button
            className="px-2 py-1 border rounded text-sm"
            onClick={() => { try { window.location.href = '/#/settings'; } catch {} }}
            title="Settings"
          >
            Settings
          </button>
          {onClose && (
            <button className="ml-2 px-2 py-1 border rounded text-sm" onClick={onClose}>Close</button>
          )}
        </div>
      </header>

      {mode === "simple" ? (
        <SimpleAutomations
          rules={rules}
          stats={ruleStats}
          loading={rulesLoading}
          saving={rulesSaving}
          error={rulesError}
          onRefresh={async () => { await loadRules(); await loadRuleStats(); }}
          onOpenNew={() => {
            setDraft({
              id: "",
              name: "",
              enabled: true,
              workspaceScope: "current",
              workspaces: [],
              keywords: "",
              replyText: "",
              tag: "",
              cooldownSeconds: 0,
              triggerSource: "whatsapp",
              shopifyTopic: "orders/paid",
              shopifyTopicPreset: "orders/paid",
              shopifyTopicCustom: "",
              shopifyTaggedWith: "",
              shopifyTestPhones: "",
              deliveryStatuses: "",
              deliveryTestPhones: "",
              actionMode: "text",
              to: "{{ phone }}",
              templateName: "",
              templateLanguage: "en",
              templateVars: [],
              templateHeaderUrl: "",
              ocEntryGateMode: "tag_or_online_store", // all | tag_or_online_store
              ocRequiredTag: "easysell_cod_form",
              ocIncludeOnlineStore: true,
              ocConfirmTitles: DEFAULT_OC_CONFIRM_TITLES,
              ocChangeTitles: DEFAULT_OC_CHANGE_TITLES,
              ocTalkTitles: DEFAULT_OC_TALK_TITLES,
              ocConfirmIds: "",
              ocChangeIds: "",
              ocTalkIds: "",
              ocConfirmAudioUrl: "",
              ocChangeAudioUrl: "",
              ocTalkAudioUrl: "",
              ocSendItems: true,
              ocMaxItems: 10,
            });
            setEditorOpen(true);
          }}
          onEdit={(r) => {
            const cond = (r && r.condition) || {};
            const kws = Array.isArray(cond.keywords) ? cond.keywords : [];
            const acts = Array.isArray(r.actions) ? r.actions : [];
            const aText = acts.find((x) => String(x?.type || "").toLowerCase().includes("text")) || null;
            const aTag = acts.find((x) => String(x?.type || "").toLowerCase().includes("tag")) || null;
            const aTpl = acts.find((x) => String(x?.type || "").toLowerCase().includes("template")) || null;
            const aOC = acts.find((x) => ["order_confirmation_flow", "order_confirm_flow"].includes(String(x?.type || "").toLowerCase())) || null;
            const aButtons = acts.find((x) => String(x?.type || "").toLowerCase() === "send_buttons") || null;
            const aList = acts.find((x) => String(x?.type || "").toLowerCase() === "send_list") || null;
            const aStatus = acts.find((x) => String(x?.type || "").toLowerCase() === "shopify_order_status") || null;
            const trig = (r && r.trigger) || {};
            const source = String(trig.source || "whatsapp").toLowerCase();
            const testPhones = Array.isArray(r?.test_phone_numbers) ? r.test_phone_numbers : [];
            const testPhonesStr = testPhones.filter(Boolean).join("\n");
            const taggedWith = String(r?.condition?.match || "").toLowerCase() === "tag_contains"
              ? String(r?.condition?.value || r?.condition?.tag || "")
              : "";
            const isDelivery = source === "delivery";
            const statuses = Array.isArray(r?.condition?.statuses) ? r.condition.statuses : [];
            const statusesStr = statuses.filter(Boolean).join(", ");
            const trigEvent = String(trig?.event || "orders/paid");
            const knownTopics = new Set(
              (Array.isArray(SHOPIFY_EVENTS) ? SHOPIFY_EVENTS : [])
                .map((ev) => String(ev?.topic || "").trim())
                .filter(Boolean)
            );
            const isCustomTopic = trigEvent && !knownTopics.has(trigEvent);
            const tplVars = (() => {
              try {
                const src = aOC || aTpl;
                const comps = Array.isArray(src?.components) ? src.components : [];
                const body = comps.find((c) => String(c?.type || "").toLowerCase() === "body") || null;
                const params = Array.isArray(body?.parameters) ? body.parameters : [];
                // We currently only expose text params in the UI
                return params
                  .filter((p) => String(p?.type || "").toLowerCase() === "text")
                  .map((p) => String(p?.text || ""))
                  .filter((s) => s.trim().length > 0);
              } catch {
                return [];
              }
            })();
            const tplHeaderUrl = (() => {
              try {
                const src = aOC || aTpl;
                const comps = Array.isArray(src?.components) ? src.components : [];
                const header = comps.find((c) => String(c?.type || "").toLowerCase() === "header") || null;
                const params = Array.isArray(header?.parameters) ? header.parameters : [];
                const p0 = params[0] || null;
                if (!p0) return "";
                const t = String(p0.type || "").toLowerCase();
                if (t === "image") return String(p0.image?.link || "");
                if (t === "video") return String(p0.video?.link || "");
                if (t === "document") return String(p0.document?.link || "");
              } catch {}
              return "";
            })();
            setDraft({
              id: String(r.id || ""),
              name: String(r.name || ""),
              enabled: !!r.enabled,
              ...(function () {
                try {
                  const ws = (localStorage.getItem('workspace') || 'irranova').trim().toLowerCase() || 'irranova';
                  const scopes = Array.isArray(r?.workspaces) ? r.workspaces.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean) : null;
                  if (!scopes || scopes.length === 0) return { workspaceScope: "current", workspaces: [] };
                  if (scopes.includes('*')) return { workspaceScope: "all", workspaces: ['*'] };
                  if (scopes.length === 1 && scopes[0] === ws) return { workspaceScope: "current", workspaces: [] };
                  return { workspaceScope: "selected", workspaces: scopes };
                } catch {
                  return { workspaceScope: "current", workspaces: [] };
                }
              })(),
              keywords: kws.join(", "),
              replyText: String(aText?.text || ""),
              tag: String(aTag?.tag || ""),
              cooldownSeconds: Number(r.cooldown_seconds || 0),
              triggerSource: source === "shopify" ? "shopify" : (source === "delivery" ? "delivery" : "whatsapp"),
              waTriggerMode: (source !== "shopify" && source !== "delivery" && String(trig?.event || "").toLowerCase() === "no_reply")
                ? "no_reply"
                : (source !== "shopify" && source !== "delivery" && String(trig?.event || "").toLowerCase() === "interactive" ? "button" : "incoming"),
              noReplyMinutes: (() => {
                try {
                  const c = (r?.condition && typeof r.condition === "object") ? r.condition : {};
                  const sec = Number(c?.seconds || 0);
                  if (Number.isFinite(sec) && sec > 0) return Math.max(1, Math.round(sec / 60));
                } catch {}
                return 30;
              })(),
              whatsappTestPhones: (!isDelivery && source !== "shopify") ? testPhonesStr : "",
              waNoUrlNoDigit: String(r?.condition?.match || "").toLowerCase() === "no_url_no_digit",
              buttonIds: (() => {
                try {
                  const m = String(r?.condition?.match || "").toLowerCase();
                  if (m === "button_id" || m === "interactive_id") {
                    const v = String(r?.condition?.value || "").trim();
                    const ids = Array.isArray(r?.condition?.ids) ? r.condition.ids : [];
                    const arr = v ? [v] : ids;
                    return (arr || []).map((x) => String(x || "").trim()).filter(Boolean).join("\n");
                  }
                } catch {}
                return "";
              })(),
              shopifyTopic: trigEvent || "orders/paid",
              shopifyTopicPreset: isCustomTopic ? "orders/paid" : (trigEvent || "orders/paid"),
              shopifyTopicCustom: isCustomTopic ? trigEvent : "",
              shopifyTaggedWith: taggedWith,
              shopifyTestPhones: testPhonesStr,
              shopifyTagOnSent: String((aText?.shopify_tag_on_sent || aTpl?.shopify_tag_on_sent || aOC?.shopify_tag_on_sent) || ""),
              deliveryStatuses: isDelivery ? statusesStr : "",
              deliveryTestPhones: isDelivery ? testPhonesStr : "",
              actionMode: aStatus ? "order_status" : (aButtons ? "buttons" : (aList ? "list" : (aOC ? "order_confirm" : (aTpl ? "template" : "text")))),
              to: String((aText?.to || aTpl?.to || aOC?.to) || "{{ phone }}"),
              templateName: String(aTpl?.template_name || aOC?.template_name || ""),
              templateLanguage: String(aTpl?.language || aOC?.language || "en"),
              templateVars: tplVars,
              templateHeaderUrl: tplHeaderUrl,
              buttonsText: String(aButtons?.text || aButtons?.message || ""),
              buttonsLines: (() => {
                try {
                  const bs = Array.isArray(aButtons?.buttons) ? aButtons.buttons : [];
                  return bs
                    .map((b) => `${String(b?.id || "").trim()}|${String(b?.title || "").trim()}`)
                    .filter((x) => {
                      const parts = x.split("|");
                      return String(parts[0] || "").trim() && String(parts[1] || "").trim();
                    })
                    .join("\n");
                } catch {
                  return "";
                }
              })(),
              listText: String(aList?.text || aList?.message || ""),
              listButtonText: String(aList?.button_text || "Choose"),
              listSectionTitle: String((((Array.isArray(aList?.sections) ? aList.sections : [])[0] || {})?.title) || ""),
              listRowsLines: (() => {
                try {
                  const secs = Array.isArray(aList?.sections) ? aList.sections : [];
                  const rows = Array.isArray(secs?.[0]?.rows) ? secs[0].rows : [];
                  return rows
                    .map((r0) => {
                      const id = String(r0?.id || "").trim();
                      const title = String(r0?.title || "").trim();
                      const desc = String(r0?.description || "").trim();
                      if (!id || !title) return "";
                      return desc ? `${id}|${title}|${desc}` : `${id}|${title}`;
                    })
                    .filter(Boolean)
                    .join("\n");
                } catch {
                  return "";
                }
              })(),
              ocEntryGateMode: String(aOC?.entry_gate_mode || "all"),
              ocRequiredTag: String(aOC?.required_tag || "easysell_cod_form"),
              ocIncludeOnlineStore: aOC?.include_online_store !== undefined ? !!aOC.include_online_store : true,
              ocConfirmTitles: Array.isArray(aOC?.confirm_titles) ? aOC.confirm_titles.filter(Boolean).join("\n") : DEFAULT_OC_CONFIRM_TITLES,
              ocChangeTitles: Array.isArray(aOC?.change_titles) ? aOC.change_titles.filter(Boolean).join("\n") : DEFAULT_OC_CHANGE_TITLES,
              ocTalkTitles: Array.isArray(aOC?.talk_titles) ? aOC.talk_titles.filter(Boolean).join("\n") : DEFAULT_OC_TALK_TITLES,
              ocConfirmIds: Array.isArray(aOC?.confirm_ids) ? aOC.confirm_ids.filter(Boolean).join("\n") : "",
              ocChangeIds: Array.isArray(aOC?.change_ids) ? aOC.change_ids.filter(Boolean).join("\n") : "",
              ocTalkIds: Array.isArray(aOC?.talk_ids) ? aOC.talk_ids.filter(Boolean).join("\n") : "",
              ocConfirmAudioUrl: String(aOC?.confirm_audio_url || ""),
              ocChangeAudioUrl: String(aOC?.change_audio_url || ""),
              ocTalkAudioUrl: String(aOC?.talk_audio_url || ""),
              ocSendItems: aOC?.send_items === undefined ? true : !!aOC.send_items,
              ocMaxItems: Number(aOC?.max_items || 10),
            });
            setEditorOpen(true);
          }}
          onToggle={async (id, enabled) => {
            const next = (rules || []).map((r) => (r.id === id ? { ...r, enabled } : r));
            await persistRules(next);
            await loadRuleStats();
          }}
          onDelete={async (id) => {
            if (!window.confirm("Delete this automation?")) return;
            const next = (rules || []).filter((r) => r.id !== id);
            await persistRules(next);
            await loadRuleStats();
          }}
        >
          {editorOpen && (
            <RuleEditor
              draft={draft}
              workspaceOptions={workspaceOptions}
              currentWorkspace={currentWorkspace}
              deliveryStatusOptions={deliveryStatusOptions}
              templates={templates}
              templatesLoading={templatesLoading}
              templatesError={templatesError}
              saving={rulesSaving}
              onClose={() => setEditorOpen(false)}
              onChange={(p) => setDraft((d) => ({ ...d, ...p }))}
              onSave={async () => {
                const newId = draft.id || `r_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
                const kws = String(draft.keywords || "")
                  .split(",")
                  .map((x) => x.trim())
                  .filter(Boolean);
                const whatsappTestPhones = String(draft.whatsappTestPhones || "")
                  .split(/\r?\n|,/g)
                  .map((x) => x.trim())
                  .filter(Boolean);
                const buttonIds = String(draft.buttonIds || "")
                  .split(/\r?\n|,/g)
                  .map((x) => x.trim())
                  .filter(Boolean);
                const testPhones = String(draft.shopifyTestPhones || "")
                  .split(/\r?\n|,/g)
                  .map((x) => x.trim())
                  .filter(Boolean);
                const deliveryTestPhones = String(draft.deliveryTestPhones || "")
                  .split(/\r?\n|,/g)
                  .map((x) => x.trim())
                  .filter(Boolean);
                const deliveryStatuses = String(draft.deliveryStatuses || "")
                  .split(/\r?\n|,/g)
                  .map((x) => x.trim())
                  .filter(Boolean);
                const shopifyTopicEffective =
                  String(draft.shopifyTopicCustom || "").trim() ||
                  String(draft.shopifyTopicPreset || draft.shopifyTopic || "orders/paid").trim() ||
                  "orders/paid";
                const actions = [];
                const listFromLines = (s) =>
                  String(s || "")
                    .split(/\r?\n|,/g)
                    .map((x) => x.trim())
                    .filter(Boolean);
                const ruleWorkspaces = (() => {
                  try {
                    const scope = String(draft.workspaceScope || 'current').toLowerCase();
                    if (scope === 'all') return ['*'];
                    if (scope === 'selected') {
                      const list = Array.isArray(draft.workspaces) ? draft.workspaces : [];
                      const cleaned = list.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean);
                      return cleaned.length ? cleaned : [currentWorkspace];
                    }
                    return [currentWorkspace];
                  } catch {
                    return [currentWorkspace];
                  }
                })();

                const shopifyTagOnSent = String(draft.shopifyTagOnSent || "").trim();

                if (draft.actionMode === "order_confirm") {
                  const tn = String(draft.templateName || "").trim();
                  if (tn) {
                    const vars = Array.isArray(draft.templateVars) ? draft.templateVars : [];
                    const bodyParams = vars.filter((x) => String(x || "").trim()).map((v) => ({ type: "text", text: String(v) }));
                    const tplAll = Array.isArray(templates) ? templates : [];
                    const tpl =
                      tplAll.find((t) => t && t.name === tn && String(t.status || "").toLowerCase() === "approved") ||
                      tplAll.find((t) => t && t.name === tn) ||
                      null;
                    const headerMeta = (() => {
                      try {
                        const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                        const h = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
                        return String(h?.format || "").toUpperCase();
                      } catch {
                        return "";
                      }
                    })();
                    const headerUrl = String(draft.templateHeaderUrl || "").trim();
                    const headerComp = (() => {
                      if (!headerUrl) return null;
                      const fmt = String(headerMeta || "").toUpperCase();
                      if (fmt === "IMAGE") return { type: "header", parameters: [{ type: "image", image: { link: headerUrl } }] };
                      if (fmt === "VIDEO") return { type: "header", parameters: [{ type: "video", video: { link: headerUrl } }] };
                      if (fmt === "DOCUMENT") return { type: "header", parameters: [{ type: "document", document: { link: headerUrl } }] };
                      return null;
                    })();
                    const comps = [
                      ...(headerComp ? [headerComp] : []),
                      ...(bodyParams.length ? [{ type: "body", parameters: bodyParams }] : []),
                    ];
                    actions.push({
                      type: "order_confirmation_flow",
                      to: String(draft.to || "{{ phone }}"),
                      template_name: tn,
                      language: String(draft.templateLanguage || "en"),
                      components: comps,
                      preview: `[template] ${tn}`,
                      ...(draft.triggerSource === "shopify" && shopifyTagOnSent ? { shopify_tag_on_sent: shopifyTagOnSent } : {}),
                      entry_gate_mode: String(draft.ocEntryGateMode || "all"),
                      required_tag: String(draft.ocRequiredTag || "").trim(),
                      include_online_store: !!draft.ocIncludeOnlineStore,
                      confirm_titles: listFromLines(draft.ocConfirmTitles),
                      change_titles: listFromLines(draft.ocChangeTitles),
                      talk_titles: listFromLines(draft.ocTalkTitles),
                      confirm_ids: listFromLines(draft.ocConfirmIds),
                      change_ids: listFromLines(draft.ocChangeIds),
                      talk_ids: listFromLines(draft.ocTalkIds),
                      confirm_audio_url: String(draft.ocConfirmAudioUrl || "").trim(),
                      change_audio_url: String(draft.ocChangeAudioUrl || "").trim(),
                      talk_audio_url: String(draft.ocTalkAudioUrl || "").trim(),
                      send_items: !!draft.ocSendItems,
                      max_items: Number(draft.ocMaxItems || 10),
                    });
                  }
                } else if (draft.actionMode === "template") {
                  const tn = String(draft.templateName || "").trim();
                  if (tn) {
                    const vars = Array.isArray(draft.templateVars) ? draft.templateVars : [];
                    const bodyParams = vars.filter((x) => String(x || "").trim()).map((v) => ({ type: "text", text: String(v) }));
                    // NOTE: this onSave handler runs in the parent component scope.
                    // Use the in-scope `templates` list (not RuleEditor-scoped `approvedTemplates`).
                    const tplAll = Array.isArray(templates) ? templates : [];
                    const tpl =
                      tplAll.find((t) => t && t.name === tn && String(t.status || "").toLowerCase() === "approved") ||
                      tplAll.find((t) => t && t.name === tn) ||
                      null;
                    // If the selected template requires a media header (IMAGE/VIDEO/DOCUMENT),
                    // include it when a URL is provided.
                    const headerMeta = (() => {
                      try {
                        const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                        const h = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
                        const fmt = String(h?.format || "").toUpperCase();
                        return fmt; // IMAGE | VIDEO | DOCUMENT | TEXT | ...
                      } catch {
                        return "";
                      }
                    })();
                    const headerUrl = String(draft.templateHeaderUrl || "").trim();
                    const headerComp = (() => {
                      if (!headerUrl) return null;
                      const fmt = String(headerMeta || "").toUpperCase();
                      if (fmt === "IMAGE") return { type: "header", parameters: [{ type: "image", image: { link: headerUrl } }] };
                      if (fmt === "VIDEO") return { type: "header", parameters: [{ type: "video", video: { link: headerUrl } }] };
                      if (fmt === "DOCUMENT") return { type: "header", parameters: [{ type: "document", document: { link: headerUrl } }] };
                      return null;
                    })();
                    const comps = [
                      ...(headerComp ? [headerComp] : []),
                      ...(bodyParams.length ? [{ type: "body", parameters: bodyParams }] : []),
                    ];
                    actions.push({
                      type: "send_whatsapp_template",
                      to: String(draft.to || "{{ phone }}"),
                      template_name: tn,
                      language: String(draft.templateLanguage || "en"),
                      components: comps,
                      preview: `[template] ${tn}`,
                      ...(draft.triggerSource === "shopify" && shopifyTagOnSent ? { shopify_tag_on_sent: shopifyTagOnSent } : {}),
                    });
                  }
                } else if (draft.actionMode === "buttons") {
                  const body = String(draft.buttonsText || draft.replyText || "").trim();
                  const lines = String(draft.buttonsLines || "")
                    .split(/\r?\n/g)
                    .map((x) => x.trim())
                    .filter(Boolean);
                  const btns = [];
                  for (const ln of lines) {
                    const parts = ln.split("|");
                    const id = String(parts[0] || "").trim();
                    const title = String(parts.slice(1).join("|") || "").trim();
                    if (id && title) btns.push({ id, title });
                  }
                  if (body && btns.length) {
                    actions.push({
                      type: "send_buttons",
                      to: String(draft.to || "{{ phone }}"),
                      text: body,
                      buttons: btns,
                      ...(draft.triggerSource === "shopify" && shopifyTagOnSent ? { shopify_tag_on_sent: shopifyTagOnSent } : {}),
                    });
                  }
                } else if (draft.actionMode === "list") {
                  const body = String(draft.listText || draft.replyText || "").trim();
                  const buttonText = String(draft.listButtonText || "Choose").trim();
                  const sectionTitle = String(draft.listSectionTitle || "").trim();
                  const rowLines = String(draft.listRowsLines || "")
                    .split(/\r?\n/g)
                    .map((x) => x.trim())
                    .filter(Boolean);
                  const rows = [];
                  for (const ln of rowLines) {
                    const parts = ln.split("|");
                    const id = String(parts[0] || "").trim();
                    const title = String(parts[1] || "").trim();
                    const desc = String(parts.slice(2).join("|") || "").trim();
                    if (!id || !title) continue;
                    const row = { id, title };
                    if (desc) row.description = desc;
                    rows.push(row);
                  }
                  if (body && rows.length) {
                    actions.push({
                      type: "send_list",
                      to: String(draft.to || "{{ phone }}"),
                      text: body,
                      button_text: buttonText,
                      sections: [{ ...(sectionTitle ? { title: sectionTitle } : {}), rows }],
                      ...(draft.triggerSource === "shopify" && shopifyTagOnSent ? { shopify_tag_on_sent: shopifyTagOnSent } : {}),
                    });
                  }
                } else if (draft.actionMode === "order_status") {
                  actions.push({ type: "shopify_order_status" });
                } else {
                  if ((draft.replyText || "").trim()) {
                    actions.push({
                      type: "send_text",
                      to: String(draft.to || "{{ phone }}"),
                      text: String(draft.replyText || ""),
                      ...(draft.triggerSource === "shopify" && shopifyTagOnSent ? { shopify_tag_on_sent: shopifyTagOnSent } : {}),
                    });
                  }
                }
                if ((draft.tag || "").trim()) actions.push({ type: "add_tag", tag: String(draft.tag || "").trim() });
                const tagged = String(draft.shopifyTaggedWith || "").trim();
                const rule = {
                  id: newId,
                  name: draft.name || "WhatsApp Auto-reply",
                  enabled: !!draft.enabled,
                  workspaces: ruleWorkspaces,
                  cooldown_seconds: Number(draft.cooldownSeconds || 0),
                  trigger:
                    draft.triggerSource === "shopify"
                      ? { source: "shopify", event: String(shopifyTopicEffective || "orders/paid") }
                      : draft.triggerSource === "delivery"
                        ? { source: "delivery", event: "order_status_changed" }
                        : {
                          source: "whatsapp",
                          event: (
                            String(draft.waTriggerMode || "incoming") === "no_reply"
                              ? "no_reply"
                              : (String(draft.waTriggerMode || "incoming") === "button" ? "interactive" : "incoming_message")
                          ),
                        },
                  condition:
                    draft.triggerSource === "shopify" && tagged
                      ? { match: "tag_contains", value: tagged }
                      : draft.triggerSource === "delivery"
                        ? (deliveryStatuses.length ? { match: "status_in", statuses: deliveryStatuses } : { match: "any" })
                        : (String(draft.waTriggerMode || "incoming") === "no_reply"
                          ? { match: "no_reply_for", seconds: Math.max(60, Number(draft.noReplyMinutes || 30) * 60), keywords: kws }
                          : (String(draft.waTriggerMode || "incoming") === "button"
                            ? { match: "button_id", ids: buttonIds }
                            : (draft.waNoUrlNoDigit ? { match: "no_url_no_digit" } : { match: "contains", keywords: kws })
                          )),
                  ...(draft.triggerSource === "shopify"
                    ? { test_phone_numbers: testPhones }
                    : draft.triggerSource === "delivery"
                      ? { test_phone_numbers: deliveryTestPhones }
                      : (whatsappTestPhones.length ? { test_phone_numbers: whatsappTestPhones } : {})),
                  actions,
                };
                const next = (() => {
                  const arr = Array.isArray(rules) ? [...rules] : [];
                  const idx = arr.findIndex((r) => r.id === newId);
                  if (idx === -1) return [...arr, rule];
                  arr[idx] = { ...arr[idx], ...rule, id: arr[idx].id };
                  return arr;
                })();
                await persistRules(next);
                await loadRuleStats();
                setEditorOpen(false);
              }}
            />
          )}
        </SimpleAutomations>
      ) : mode === "templates" ? (
        <WhatsAppTemplatesPanel
          templates={templates}
          loading={templatesLoading}
          error={templatesError}
          onRefresh={loadTemplates}
        />
      ) : (
        <>
          <div className="grid grid-cols-12 gap-3 p-3 h-[calc(100vh-3rem)]">
          <aside className="col-span-12 md:col-span-3 space-y-3 overflow-y-auto pb-20">
          <div className="border rounded">
            <div className="px-3 py-2 border-b text-sm font-medium flex items-center gap-2"><Webhook className="w-4 h-4"/>Triggers</div>
            <div className="p-2 grid gap-2">
              {TRIGGERS.map((t) => (
                <PaletteItem key={t.id} icon={t.icon} label={t.label} onAdd={() => addNode(t)} />
              ))}
            </div>
          </div>
          <div className="border rounded">
            <div className="px-3 py-2 border-b text-sm font-medium flex items-center gap-2"><GitBranch className="w-4 h-4"/>Logic</div>
            <div className="p-2 grid gap-2">
              {LOGIC.map((l) => (
                <PaletteItem key={l.id} icon={l.icon} label={l.label} onAdd={() => addNode(l)} />
              ))}
            </div>
          </div>
          <div className="border rounded">
            <div className="px-3 py-2 border-b text-sm font-medium flex items-center gap-2"><Settings2 className="w-4 h-4"/>Actions</div>
            <div className="p-2 grid gap-2">
              {ACTIONS.map((a) => (
                <PaletteItem key={a.id} icon={a.icon} label={a.label} onAdd={() => addNode(a)} />
              ))}
            </div>
          </div>

          {/* Environment panel removed: studio uses same environment as inbox */}
        </aside>

        <section className="col-span-12 md:col-span-6 relative">
          <div className="flex items-center justify-between px-2 py-1">
            <div className="text-sm text-slate-500">Canvas</div>
            <div className="flex items-center gap-2">
              <div className="text-xs text-slate-500">Zoom</div>
              <input
                type="range"
                min="50"
                max="140"
                step="10"
                value={zoom * 100}
                onChange={(e)=>setZoom(Number(e.target.value)/100)}
                className="w-40"
              />
            </div>
          </div>
          <div
            className="relative h-[calc(100%-2rem)] bg-white rounded-2xl shadow-inner overflow-hidden border"
            onMouseMove={onMouseMove}
            onMouseUp={onMouseUp}
            onMouseDown={onCanvasDown}
            data-canvas
            ref={canvasRef}
          >
            <GridBackdrop />
            <div className="absolute left-0 top-0 origin-top-left" style={{ transform: `scale(${zoom})`, transformOrigin: "0 0" }}>
              {flow.edges.map((e) => (
                <Edge key={e.id} edge={e} nodes={flow.nodes} onDelete={() => deleteEdge(e.id)} active={running && activeNodeId && e.from===activeNodeId} />
              ))}
              {flow.nodes.map((n) => (
                <NodeShell
                  key={n.id}
                  node={n}
                  selected={selected === n.id}
                  onMouseDown={onNodeMouseDown}
                  onStartLink={startLink}
                  onCompleteLink={completeLink}
                  onDelete={deleteNode}
                  active={running && activeNodeId === n.id}
                />
              ))}
              {linking && <div className="absolute inset-0 pointer-events-none" />}
            </div>
          </div>
        </section>

        <aside className="col-span-12 md:col-span-3 space-y-3 overflow-y-auto pb-20">
          <div className="border rounded">
            <div className="px-3 py-2 border-b text-sm font-medium flex items-center justify-between">
              <span>Inspector</span>
              {selectedNode && (
                <button className="p-1 rounded hover:bg-slate-100" onClick={()=>deleteNode(selectedNode.id)}>
                  <Trash className="w-4 h-4" />
                </button>
              )}
            </div>
            <div className="p-2">
              {!selectedNode && (
                <div className="text-sm text-slate-500">Select a node to edit its settings.</div>
              )}
              {selectedNode && <Inspector node={selectedNode} onUpdate={onUpdateSelected} />}
            </div>
          </div>

          <div className="border rounded">
            <div className="px-3 py-2 border-b text-sm font-medium">Flow settings</div>
            <div className="p-3 space-y-2 text-xs text-slate-600">
              <label className="flex items-center gap-2">
                <input type="checkbox" defaultChecked />
                Enabled
              </label>
              <div>
                • Flows run on your Automation API.
                <br />• Use templates for messages outside the 24‑hour window.
              </div>
            </div>
          </div>
        </aside>
        </div>

          <footer className="fixed bottom-3 left-0 right-0 flex justify-center">
            <div className="flex items-center gap-2 bg-white/80 backdrop-blur rounded-full shadow px-3 py-2 border">
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-100 text-emerald-700 inline-flex items-center gap-1"><CheckCircle2 className="w-3 h-3"/>Validated</span>
              <span className="text-xs text-slate-500">No errors</span>
              <div className="w-px h-5 bg-slate-300 mx-1"/>
              <button className="px-2 py-1 border rounded text-sm" onClick={simulate} disabled={running}><span className="inline-flex items-center gap-1"><Play className="w-4 h-4"/>Test</span></button>
              <button className="px-2 py-1 border rounded text-sm" onClick={()=>alert("Saved!")}><span className="inline-flex items-center gap-1"><Save className="w-4 h-4"/>Save</span></button>
              <button className="px-2 py-1 rounded text-sm bg-blue-600 text-white" onClick={()=>alert("Published!")}><span className="inline-flex items-center gap-1"><CirclePlay className="w-4 h-4"/>Publish</span></button>
            </div>
          </footer>
        </>
      )}
    </div>
  );
}

function PaletteItem({ icon, label, onAdd }) {
  return (
    <button onClick={onAdd} className="group flex items-center justify-between w-full rounded-xl border p-2 hover:bg-slate-50 transition shadow-sm">
      <div className="flex items-center gap-2">
        <span className="p-2 rounded-lg bg-blue-50 text-blue-600">{icon}</span>
        <span className="text-sm text-left">{label}</span>
      </div>
      <Plus className="w-4 h-4 text-slate-400 group-hover:text-slate-700" />
    </button>
  );
}

function NodeShell({ node, selected, onMouseDown, onStartLink, onCompleteLink, onDelete, active }) {
  const style = { left: node.x, top: node.y };
  const ring = selected ? "ring-2 ring-blue-500" : "ring-1 ring-slate-200";
  const glow = active ? "shadow-[0_0_0_4px_rgba(59,130,246,0.15)]" : "";

  return (
    <div className="absolute select-none" style={style} onMouseDown={(e) => onMouseDown(e, node)}>
      <div className={`rounded-2xl bg-white border ${ring} shadow ${glow} w-[240px]`}>
        <div className="px-3 py-2 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={`text-[11px] px-1.5 py-0.5 rounded border ${badgeClass(node.type)}`}>{labelForType(node.type)}</span>
          </div>
          <div className="flex items-center gap-1">
            <button className="p-1 rounded hover:bg-slate-50" onClick={(e)=>{e.stopPropagation(); onDelete(node.id);}}>
              <Trash className="w-3.5 h-3.5 text-slate-500" />
            </button>
          </div>
        </div>
        <div className="border-t" />
        <div className="p-3 text-sm text-slate-700 min-h-[56px]">{renderNodeBody(node)}</div>
        <div className="px-3 pb-3 flex items-center justify-between">
          <Port onDown={() => onStartLink(node.id, PORT.IN)} align="left" label="in" hidden={node.type===NODE_TYPES.TRIGGER} />
          {node.type === NODE_TYPES.CONDITION ? (
            <div className="flex items-center gap-3">
              <Port onUp={() => onCompleteLink(node.id, "true")} align="right" color="emerald" label="yes" />
              <Port onUp={() => onCompleteLink(node.id, "false")} align="right" color="rose" label="no" />
            </div>
          ) : (
            <Port onUp={() => onCompleteLink(node.id, PORT.OUT)} align="right" label="out" />
          )}
        </div>
      </div>
    </div>
  );
}

function Port({ align = "left", label, onDown, onUp, color = "blue", hidden }) {
  if (hidden) return <div className="h-4"/>;
  const base = color === "emerald" ? "bg-emerald-500" : color === "rose" ? "bg-rose-500" : "bg-blue-500";
  return (
    <div className={`flex ${align === "left" ? "justify-start" : "justify-end"} items-center w-full`}>
      {align === "left" && <span className="text-[10px] text-slate-400 mr-2 uppercase">{label}</span>}
      <button
        onMouseDown={onDown}
        onMouseUp={onUp}
        className={`w-3 h-3 rounded-full ${base} shadow ring-4 ring-white hover:scale-125 transition`}
        title={label}
      />
      {align === "right" && <span className="text-[10px] text-slate-400 ml-2 uppercase">{label}</span>}
    </div>
  );
}

function labelForType(t){
  return t===NODE_TYPES.TRIGGER?"Trigger":t===NODE_TYPES.CONDITION?"Condition":t===NODE_TYPES.ACTION?"Action":t===NODE_TYPES.DELAY?"Delay":"Exit";
}
function badgeClass(t){
  return t===NODE_TYPES.TRIGGER?"border-blue-200 text-blue-700 bg-blue-50":
         t===NODE_TYPES.CONDITION?"border-amber-200 text-amber-700 bg-amber-50":
         t===NODE_TYPES.ACTION?"border-emerald-200 text-emerald-700 bg-emerald-50":
         t===NODE_TYPES.DELAY?"border-purple-200 text-purple-700 bg-purple-50":"border-slate-200";
}

function renderNodeBody(node){
  switch(node.type){
    case NODE_TYPES.TRIGGER:
      return (
        <div className="space-y-2">
          <div className="text-xs text-slate-500">{String(node.data.source)} / {String(node.data.topic)}</div>
          {node.data.sample && (
            <details className="text-xs">
              <summary className="cursor-pointer text-slate-500">Sample payload</summary>
              <pre className="bg-slate-50 p-2 rounded mt-1 overflow-x-auto">{node.data.sample}</pre>
            </details>
          )}
        </div>
      );
    case NODE_TYPES.CONDITION:
      return (
        <div className="text-xs">
          <div className="font-medium text-slate-600 mb-1">Expression</div>
          <div className="font-mono bg-slate-50 rounded p-2">{String(node.data.expression)}</div>
          <div className="mt-2 flex gap-2">
            <span className="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700">{node.data.trueLabel || "Yes"}</span>
            <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-700">{node.data.falseLabel || "No"}</span>
          </div>
        </div>
      );
    case NODE_TYPES.ACTION:
      return (
        <div className="text-xs space-y-1">
          <div className="text-slate-500">{String(node.data.type)}</div>
          {node.data.template_name && <div>template: <span className="font-mono">{String(node.data.template_name)}</span></div>}
          {node.data.text && <div className="line-clamp-2">“{String(node.data.text)}”</div>}
        </div>
      );
    case NODE_TYPES.DELAY:
      return <div className="text-xs">Wait <span className="font-semibold">{String(node.data.minutes)}</span> minutes</div>;
    default:
      return null;
  }
}

function GridBackdrop(){
  return (
    <div className="absolute inset-0">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,_#eef2ff_1px,transparent_1px),linear-gradient(to_bottom,_#eef2ff_1px,transparent_1px)] bg-[size:24px_24px]"/>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(59,130,246,0.06),transparent_30%),radial-gradient(circle_at_80%_60%,rgba(14,165,233,0.06),transparent_35%)]"/>
    </div>
  );
}

function Edge({ edge, nodes, onDelete, active }){
  const from = nodes.find((n)=>n.id===edge.from);
  const to = nodes.find((n)=>n.id===edge.to);
  if(!from || !to) return null;
  const x1 = from.x + 230;
  const y1 = from.y + 100;
  const x2 = to.x + 10;
  const y2 = to.y + 100;
  const d = makePath(x1,y1,x2,y2);
  return (
    <svg className="absolute overflow-visible pointer-events-none" style={{left:0, top:0}}>
      <path d={d} className={`fill-none ${active ? 'stroke-blue-300' : 'stroke-slate-300'}`} strokeWidth={active?3:2} />
      <g className="pointer-events-auto" onClick={onDelete}>
        <circle cx={(x1+x2)/2} cy={(y1+y2)/2} r="6" className="fill-white stroke-slate-300 hover:stroke-rose-500 hover:fill-rose-50 cursor-pointer" />
      </g>
    </svg>
  );
}

function makePath(x1,y1,x2,y2){
  const c = 0.4 * Math.abs(x2-x1);
  return `M ${x1} ${y1} C ${x1+c} ${y1}, ${x2-c} ${y2}, ${x2} ${y2}`;
}

function Inspector({ node, onUpdate }){
  if(node.type === NODE_TYPES.TRIGGER){
    const isShopify = String(node.data.source||'').toLowerCase() === 'shopify' || !node.data.source;
    const selected = SHOPIFY_EVENTS.find(ev => ev.topic === node.data.topic) || null;
    return (
      <div className="space-y-3 text-sm">
        <div>
          <div className="text-xs text-slate-500 mb-1">Provider</div>
          <select
            className="w-full border rounded px-2 py-1"
            value={isShopify ? 'shopify' : (node.data.source || 'whatsapp')}
            onChange={(e)=>{
              const v = e.target.value;
              if (v === 'shopify') onUpdate({ source: 'shopify' });
              else onUpdate({ source: v, topic: v==='whatsapp' ? 'message' : (node.data.topic||'') });
            }}
          >
            <option value="shopify">Shopify</option>
            <option value="whatsapp">WhatsApp</option>
          </select>
        </div>

        {isShopify ? (
          <>
            <div>
              <div className="text-xs text-slate-500 mb-1">Shopify Event</div>
              <select
                className="w-full border rounded px-2 py-1"
                value={selected?.topic || node.data.topic || ''}
                onChange={(e)=>{
                  const ev = SHOPIFY_EVENTS.find(x=>x.topic===e.target.value);
                  if (ev) onUpdate({ source: 'shopify', topic: ev.topic, sample: ev.sample });
                  else onUpdate({ source: 'shopify', topic: e.target.value });
                }}
              >
                <option value="">Select event…</option>
                {SHOPIFY_EVENTS.map(ev => (
                  <option key={ev.id} value={ev.topic}>{ev.label}</option>
                ))}
              </select>
            </div>

            {!!selected && (
              <div>
                <div className="text-xs text-slate-500 mb-1">Variables</div>
                <div className="flex flex-wrap gap-1">
                  {selected.variables.map(v => (
                    <button
                      key={v}
                      type="button"
                      className="px-2 py-0.5 rounded border text-xs hover:bg-slate-50"
                      title="Click to copy"
                      onClick={()=>{ try { navigator.clipboard.writeText(`{{ ${v} }}`); } catch(_) {} }}
                    >{v}</button>
                  ))}
                </div>
              </div>
            )}

            <div>
              <div className="text-xs text-slate-500 mb-1">Sample Payload</div>
              <textarea className="w-full border rounded px-2 py-1" value={node.data.sample||selected?.sample||""} onChange={(e)=>onUpdate({sample:e.target.value})} rows={5} />
            </div>
          </>
        ) : (
          <>
            <div>
              <div className="text-xs text-slate-500 mb-1">Topic</div>
              <input className="w-full border rounded px-2 py-1" value={node.data.topic||""} onChange={(e)=>onUpdate({topic:e.target.value})} />
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Sample Payload</div>
              <textarea className="w-full border rounded px-2 py-1" value={node.data.sample||""} onChange={(e)=>onUpdate({sample:e.target.value})} rows={5} />
            </div>
          </>
        )}
      </div>
    );
  }
  if(node.type === NODE_TYPES.CONDITION){
    return (
      <div className="space-y-3 text-sm">
        <div>
          <div className="text-xs text-slate-500 mb-1">Expression (Jinja / JSONLogic)</div>
          <textarea className="w-full border rounded px-2 py-1" value={node.data.expression||""} onChange={(e)=>onUpdate({expression:e.target.value})} rows={3} />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <div className="text-xs text-slate-500 mb-1">Yes label</div>
            <input className="w-full border rounded px-2 py-1" value={node.data.trueLabel||"Yes"} onChange={(e)=>onUpdate({trueLabel:e.target.value})} />
          </div>
          <div>
            <div className="text-xs text-slate-500 mb-1">No label</div>
            <input className="w-full border rounded px-2 py-1" value={node.data.falseLabel||"No"} onChange={(e)=>onUpdate({falseLabel:e.target.value})} />
          </div>
        </div>
      </div>
    );
  }
  if(node.type === NODE_TYPES.ACTION){
    const isTemplate = String(node.data.type||"") === "send_whatsapp_template";
    return (
      <div className="text-sm">
        <div className="flex gap-2 mb-2">
          <button className={`px-2 py-1 border rounded ${isTemplate? 'bg-blue-50 border-blue-200' : ''}`} onClick={()=>onUpdate({ type: 'send_whatsapp_template' })}>Template</button>
          <button className={`px-2 py-1 border rounded ${!isTemplate? 'bg-blue-50 border-blue-200' : ''}`} onClick={()=>onUpdate({ type: 'send_whatsapp_text' })}>Text</button>
        </div>
        {isTemplate ? (
          <div className="space-y-3">
            <div>
              <div className="text-xs text-slate-500 mb-1">To</div>
              <input className="w-full border rounded px-2 py-1" value={node.data.to||""} onChange={(e)=>onUpdate({to:e.target.value})} />
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Template name</div>
              <input className="w-full border rounded px-2 py-1" value={node.data.template_name||""} onChange={(e)=>onUpdate({template_name:e.target.value})} />
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Language</div>
              <input className="w-full border rounded px-2 py-1" value={node.data.language||"en"} onChange={(e)=>onUpdate({language:e.target.value})} />
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Body variable 1</div>
              <input className="w-full border rounded px-2 py-1" placeholder="{{ order_number }}" onChange={(e)=>{
                const comps = [{ type:"body", parameters:[{ type:"text", text:e.target.value||"" }] }];
                onUpdate({ components: comps });
              }} />
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <div className="text-xs text-slate-500 mb-1">To</div>
              <input className="w-full border rounded px-2 py-1" value={node.data.to||""} onChange={(e)=>onUpdate({to:e.target.value})} />
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Message</div>
              <textarea className="w-full border rounded px-2 py-1" rows={5} value={node.data.text||""} onChange={(e)=>onUpdate({text:e.target.value})} />
            </div>
          </div>
        )}
      </div>
    );
  }
  if(node.type === NODE_TYPES.DELAY){
    return (
      <div className="space-y-3 text-sm">
        <div>
          <div className="text-xs text-slate-500 mb-1">Minutes</div>
          <input type="number" className="w-full border rounded px-2 py-1" value={node.data.minutes||0} onChange={(e)=>onUpdate({minutes:Number(e.target.value||0)})} />
        </div>
      </div>
    );
  }
  return <div className="text-sm text-slate-500">No settings.</div>;
}

function SimpleAutomations({ rules, stats, loading, saving, error, onRefresh, onOpenNew, onEdit, onToggle, onDelete, children }) {
  return (
    <div className="p-4 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-lg font-semibold">WhatsApp Automations</div>
          <div className="text-sm text-slate-500">Real-time automations connected to the inbox (trigger on incoming WhatsApp messages).</div>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 border rounded text-sm" onClick={onRefresh} disabled={loading || saving}>Refresh</button>
          <button className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white" onClick={onOpenNew} disabled={loading || saving}>+ New rule</button>
        </div>
      </div>

      {error && <div className="mb-3 p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{error}</div>}
      {loading && <div className="text-sm text-slate-500">Loading…</div>}

      {!loading && (
        <div className="grid gap-2">
          {(rules || []).length === 0 ? (
            <div className="p-4 rounded border bg-white text-sm text-slate-500">No automations yet. Create your first rule.</div>
          ) : (
            (rules || []).map((r) => {
              const s = (stats && r && r.id && stats[r.id]) ? stats[r.id] : {};
              const triggers = Number(s?.triggers || 0);
              const sent = Number(s?.messages_sent || 0);
              const last = s?.last_trigger_ts || null;
              return (
                <div key={r.id} className="p-3 rounded border bg-white flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="font-semibold truncate">{r.name || r.id}</div>
                      <span className={`text-xs px-2 py-0.5 rounded ${r.enabled ? "bg-emerald-100 text-emerald-700" : "bg-slate-100 text-slate-600"}`}>
                        {r.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </div>
                    <div className="text-xs text-slate-500 mt-1 truncate">
                      Trigger: {String(r?.trigger?.source || "whatsapp") === "shopify"
                        ? `Shopify webhook (${String(r?.trigger?.event || "")})`
                        : String(r?.trigger?.source || "whatsapp") === "delivery"
                          ? "Delivery status"
                          : "WhatsApp incoming message"}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs">
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700">Triggers: {triggers}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700">Messages sent: {sent}</span>
                      {last && <span className="px-2 py-0.5 rounded bg-slate-50 text-slate-600">Last: {String(last).slice(0, 19).replace('T',' ')}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <label className="text-sm flex items-center gap-2">
                      <input type="checkbox" checked={!!r.enabled} onChange={(e) => onToggle(r.id, e.target.checked)} />
                      On
                    </label>
                    <button className="px-2 py-1 border rounded text-sm" onClick={() => onEdit(r)}>Edit</button>
                    <button className="px-2 py-1 border rounded text-sm text-rose-700 border-rose-200" onClick={() => onDelete(r.id)}>Delete</button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {children}

      <div className="mt-6 text-xs text-slate-500">
        Tip: after enabling a rule, send a WhatsApp message matching the keywords and you should see the auto-reply appear instantly in the same conversation.
      </div>
    </div>
  );
}

function MultiSelectDropdown({ label, options, selected, onChange, placeholder = "Select…" }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const ref = useRef(null);

  useEffect(() => {
    const onDoc = (e) => {
      try {
        if (!ref.current) return;
        if (ref.current.contains(e.target)) return;
        setOpen(false);
      } catch {}
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const normalizedOptions = useMemo(() => {
    const arr = Array.isArray(options) ? options : [];
    const seen = new Set();
    const out = [];
    for (const x of arr) {
      const s = String(x || "").trim();
      if (!s) continue;
      const k = s.toLowerCase();
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(s);
    }
    return out;
  }, [options]);

  const filtered = useMemo(() => {
    const qq = String(q || "").trim().toLowerCase();
    if (!qq) return normalizedOptions;
    return normalizedOptions.filter((x) => x.toLowerCase().includes(qq));
  }, [normalizedOptions, q]);

  const sel = Array.isArray(selected) ? selected : [];
  const summary = (() => {
    if (!sel.length) return placeholder;
    if (sel.length <= 2) return sel.join(", ");
    return `${sel.slice(0, 2).join(", ")} +${sel.length - 2}`;
  })();

  const toggle = (opt) => {
    const key = String(opt || "").trim();
    if (!key) return;
    const exists = sel.map((x) => String(x || "").trim().toLowerCase()).includes(key.toLowerCase());
    if (exists) {
      onChange(sel.filter((x) => String(x || "").trim().toLowerCase() !== key.toLowerCase()));
    } else {
      onChange([...sel, key]);
    }
  };

  return (
    <div ref={ref} className="relative">
      <div className="text-xs text-slate-500 mb-1">{label}</div>
      <button
        type="button"
        className="w-full flex items-center justify-between gap-2 border rounded-lg px-3 py-2 text-sm bg-white hover:bg-slate-50"
        onClick={() => setOpen((v) => !v)}
      >
        <span className={`truncate ${sel.length ? "text-slate-900" : "text-slate-500"}`}>{summary}</span>
        <span className="text-slate-400">▾</span>
      </button>
      {open && (
        <div className="absolute mt-2 w-full z-50 bg-white border rounded-xl shadow-lg p-2">
          <div className="flex items-center gap-2 mb-2">
            <input
              className="w-full border rounded-lg px-2 py-1 text-sm"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search…"
            />
            <button
              type="button"
              className="px-2 py-1 text-sm border rounded-lg hover:bg-slate-50"
              onClick={() => onChange([])}
              title="Clear"
            >
              Clear
            </button>
          </div>
          <div className="max-h-56 overflow-auto pr-1">
            {filtered.length === 0 ? (
              <div className="text-sm text-slate-500 p-2">No matches.</div>
            ) : (
              filtered.map((opt) => {
                const checked = sel.map((x) => String(x || "").trim().toLowerCase()).includes(String(opt).toLowerCase());
                return (
                  <label key={`ms:${opt}`} className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-slate-50 text-sm cursor-pointer">
                    <input type="checkbox" checked={checked} onChange={() => toggle(opt)} />
                    <span className="truncate">{opt}</span>
                  </label>
                );
              })
            )}
          </div>
          {normalizedOptions.length > 0 && (
            <div className="mt-2 flex items-center justify-between">
              <div className="text-xs text-slate-500">{sel.length} selected</div>
              <button
                type="button"
                className="px-2 py-1 text-sm border rounded-lg hover:bg-slate-50"
                onClick={() => onChange([...normalizedOptions])}
              >
                Select all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SingleSelectDropdown({ label, options, value, onChange, placeholder = "Select…", allowClear = true }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const ref = useRef(null);

  useEffect(() => {
    const onDoc = (e) => {
      try {
        if (!ref.current) return;
        if (ref.current.contains(e.target)) return;
        setOpen(false);
      } catch {}
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const normalizedOptions = useMemo(() => {
    const arr = Array.isArray(options) ? options : [];
    const seen = new Set();
    const out = [];
    for (const x of arr) {
      const s = String(x || "").trim();
      if (!s) continue;
      const k = s.toLowerCase();
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(s);
    }
    return out;
  }, [options]);

  const filtered = useMemo(() => {
    const qq = String(q || "").trim().toLowerCase();
    if (!qq) return normalizedOptions;
    return normalizedOptions.filter((x) => x.toLowerCase().includes(qq));
  }, [normalizedOptions, q]);

  const current = String(value || "").trim();
  const summary = current ? current : placeholder;

  return (
    <div ref={ref} className="relative">
      {label ? <div className="text-xs text-slate-500 mb-1">{label}</div> : null}
      <button
        type="button"
        className="w-full flex items-center justify-between gap-2 border rounded-lg px-3 py-2 text-sm bg-white hover:bg-slate-50"
        onClick={() => setOpen((v) => !v)}
      >
        <span className={`truncate ${current ? "text-slate-900" : "text-slate-500"}`}>{summary}</span>
        <span className="text-slate-400">▾</span>
      </button>
      {open && (
        <div className="absolute mt-2 w-full z-50 bg-white border rounded-xl shadow-lg p-2">
          <div className="flex items-center gap-2 mb-2">
            <input
              className="w-full border rounded-lg px-2 py-1 text-sm"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search…"
            />
            {allowClear && (
              <button
                type="button"
                className="px-2 py-1 text-sm border rounded-lg hover:bg-slate-50"
                onClick={() => {
                  onChange("");
                  setOpen(false);
                }}
                title="Clear"
              >
                Clear
              </button>
            )}
          </div>
          <div className="max-h-56 overflow-auto">
            {filtered.length === 0 ? (
              <div className="text-sm text-slate-500 px-2 py-2">No results</div>
            ) : (
              filtered.map((opt) => {
                const isSel = String(opt).toLowerCase() === current.toLowerCase();
                return (
                  <button
                    key={`opt:${opt}`}
                    type="button"
                    className={`w-full text-left px-2 py-1.5 rounded-lg text-sm hover:bg-slate-50 flex items-center justify-between ${
                      isSel ? "bg-indigo-50" : ""
                    }`}
                    onClick={() => {
                      onChange(opt);
                      setOpen(false);
                    }}
                  >
                    <span className="truncate">{opt}</span>
                    {isSel ? <span className="text-indigo-600 text-xs">✓</span> : null}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function RuleEditor({ draft, workspaceOptions, currentWorkspace, deliveryStatusOptions, templates, templatesLoading, templatesError, saving, onClose, onChange, onSave }) {
  const [step, setStep] = useState(1); // 1..3
  const [nameTouched, setNameTouched] = useState(false);
  const initialSnapshotRef = useRef("");

  const safeSnap = (obj) => {
    try { return JSON.stringify(obj || {}); } catch { return ""; }
  };

  useEffect(() => {
    setStep(1);
    setNameTouched(false);
    initialSnapshotRef.current = safeSnap(draft);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.id]);

  const isDirty = useMemo(() => {
    try {
      const cur = safeSnap(draft);
      const base = initialSnapshotRef.current || "";
      return !!base && cur !== base;
    } catch {
      return false;
    }
  }, [draft]);

  const requestClose = () => {
    try {
      if (isDirty) {
        const ok = window.confirm("Discard unsaved changes?");
        if (!ok) return;
      }
    } catch {}
    onClose();
  };

  const parseList = (s) =>
    String(s || "")
      .split(/\r?\n|,/g)
      .map((x) => x.trim())
      .filter(Boolean);

  const deliverySelected = useMemo(() => parseList(draft.deliveryStatuses), [draft.deliveryStatuses]);

  const shopifyTopics = [
    { topic: "draft_orders/create", label: "Shopify: Draft Order Created (draft_orders/create)" },
    { topic: "orders/create", label: "Shopify: New Order (orders/create)" },
    { topic: "orders/paid", label: "Shopify: Order Paid (orders/paid)" },
    { topic: "orders/updated", label: "Shopify: Order Updated (orders/updated) — use for tags" },
    { topic: "orders/cancelled", label: "Shopify: Order Cancelled (orders/cancelled)" },
    { topic: "fulfillments/create", label: "Shopify: Fulfillment Created (fulfillments/create)" },
    { topic: "fulfillments/update", label: "Shopify: Fulfillment Updated (fulfillments/update)" },
    { topic: "customers/create", label: "Shopify: Customer Created (customers/create)" },
    { topic: "customers/update", label: "Shopify: Customer Updated (customers/update)" },
    { topic: "refunds/create", label: "Shopify: Refund Created (refunds/create)" },
  ];

  const approvedTemplates = (templates || []).filter((t) => String(t?.status || "").toLowerCase() === "approved");

  const inferBodyVarCount = (tpl) => {
    try {
      const comps = tpl?.components || [];
      const body = (Array.isArray(comps) ? comps : []).find((c) => String(c?.type || "").toUpperCase() === "BODY");
      const ex = body?.example;
      const bodyText = ex?.body_text;
      if (Array.isArray(bodyText) && Array.isArray(bodyText[0])) return bodyText[0].length;
    } catch {}
    return 0;
  };

  const shopifyVarsByTopic = (topic) => {
    try {
      const ev = (Array.isArray(SHOPIFY_EVENTS) ? SHOPIFY_EVENTS : []).find((x) => x.topic === topic);
      if (ev && Array.isArray(ev.variables)) {
        const base = ev.variables;
        // Extra common order/customer/address fields for templating (used by dropdown pickers)
        const extra = [
          "order_number",
          "total_price",
          "customer.first_name",
          "customer.last_name",
          "customer.email",
          "customer.phone",
          "shipping_address.name",
          "shipping_address.phone",
          "shipping_address.address1",
          "shipping_address.address2",
          "shipping_address.city",
          "shipping_address.province",
          "shipping_address.zip",
          "shipping_address.country",
          "billing_address.name",
          "billing_address.phone",
          "billing_address.address1",
          "billing_address.address2",
          "billing_address.city",
          "billing_address.province",
          "billing_address.zip",
          "billing_address.country",
          // Line items (use [0] syntax — supported by backend template renderer)
          "line_items[0].title",
          "line_items[0].variant_title",
          "line_items[0].quantity",
          "line_items[0].price",
          "line_items[0].sku",
          // Computed helper (backend will populate)
          "order_first_item_image_url",
        ];
        return [...base, ...extra];
      }
    } catch {}
    // minimal fallback
    return [
      "customer.phone",
      "order_number",
      "total_price",
      "shipping_address.address1",
      "shipping_address.city",
      "line_items[0].title",
      "order_first_item_image_url",
    ];
  };

  const copyVar = async (v) => {
    try { await navigator.clipboard.writeText(`{{ ${v} }}`); } catch {}
  };

  const availableVarOptions = useMemo(() => {
    // For template actions, users usually want Shopify order/customer vars even if trigger is WhatsApp.
    // NOTE: If triggerSource != shopify/delivery, only {{ phone }} and {{ text }} will have values at runtime.
    try {
      const base = ["phone", "text"];
      const topic = String(draft.shopifyTopic || "orders/paid") || "orders/paid";
      const shop = shopifyVarsByTopic(topic);
      const shopDefault = shopifyVarsByTopic("orders/paid");
      const del = DELIVERY_VARS;
      const combined =
        draft.triggerSource === "shopify"
          ? [...base, ...shop]
          : draft.triggerSource === "delivery"
            ? [...base, ...del]
            : [...base, ...shopDefault, ...shop];
      const seen = new Set();
      const out = [];
      for (const x of combined) {
        const s = String(x || "").trim();
        if (!s) continue;
        const k = s.toLowerCase();
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(s);
      }
      return out;
    } catch {
      return ["phone", "text", "order_number", "total_price", "customer.phone", "shipping_address.address1", "shipping_address.city", "order_first_item_image_url"];
    }
  }, [draft.triggerSource, draft.shopifyTopic]);

  const selectedTemplate = useMemo(() => {
    try {
      const tn = String(draft.templateName || "").trim();
      if (!tn) return null;
      return approvedTemplates.find((t) => t && t.name === tn) || null;
    } catch {
      return null;
    }
  }, [approvedTemplates, draft.templateName]);

  const selectedTemplatePreview = useMemo(() => {
    try {
      const tpl = selectedTemplate;
      if (!tpl) return null;
      const comps = Array.isArray(tpl?.components) ? tpl.components : [];
      const header = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
      const body = comps.find((c) => String(c?.type || "").toUpperCase() === "BODY") || null;
      const footer = comps.find((c) => String(c?.type || "").toUpperCase() === "FOOTER") || null;
      const buttons = comps.find((c) => String(c?.type || "").toUpperCase() === "BUTTONS") || null;
      const bodyText = String(body?.text || "").trim();
      const placeholders = [];
      const seen = new Set();
      const re = /\{\{\s*(\d{1,3})\s*\}\}/g;
      let m;
      // eslint-disable-next-line no-cond-assign
      while ((m = re.exec(bodyText))) {
        const n = String(m[1] || "").trim();
        if (!n || seen.has(n)) continue;
        seen.add(n);
        placeholders.push(n);
      }
      return {
        headerFormat: String(header?.format || "").toUpperCase(),
        bodyText,
        footerText: String(footer?.text || "").trim(),
        buttons: Array.isArray(buttons?.buttons) ? buttons.buttons : [],
        placeholders,
      };
    } catch {
      return null;
    }
  }, [selectedTemplate]);

  const steps = [
    { id: 1, label: "Setup", hint: "Name • Workspaces • Trigger" },
    { id: 2, label: "Message", hint: "Send to • Keywords • Actions" },
    { id: 3, label: "Branches", hint: "Button click branches" },
  ];

  const canGoNext = () => {
    if (step === 1) return true;
    if (step === 2) return true;
    return true;
  };

  const onNext = () => {
    if (step === 1) {
      const nm = String(draft.name || "").trim();
      setNameTouched(true);
      if (!nm) return;
    }
    setStep((s) => Math.min(3, s + 1));
  };

  const onBack = () => setStep((s) => Math.max(1, s - 1));

  const canSave = useMemo(() => {
    const nm = String(draft.name || "").trim();
    if (!nm) return false;
    const tagOk = !!String(draft.tag || "").trim();
    if (draft.actionMode === "text") {
      return tagOk || !!String(draft.replyText || "").trim();
    }
    if (draft.actionMode === "buttons") {
      const bodyOk = !!String(draft.buttonsText || "").trim();
      const hasBtn = String(draft.buttonsLines || "").trim().length > 0;
      return tagOk || (bodyOk && hasBtn);
    }
    if (draft.actionMode === "list") {
      const bodyOk = !!String(draft.listText || "").trim();
      const hasRows = String(draft.listRowsLines || "").trim().length > 0;
      return tagOk || (bodyOk && hasRows);
    }
    if (draft.actionMode === "order_status") {
      return true; // built-in lookup action (no extra input required)
    }
    // template / order_confirm require a selected template (tag-only rules are allowed, but rarely intended)
    return !!String(draft.templateName || "").trim() || tagOk;
  }, [draft]);

  return (
    <div className="fixed inset-0 bg-black/40 z-[100] flex items-center justify-center p-3">
      <div className="w-[780px] max-w-[95vw] bg-white rounded-2xl border shadow-2xl overflow-hidden">
        <div className="px-4 py-3 border-b bg-white/80 backdrop-blur">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <div className="font-semibold truncate">{draft.id ? "Edit rule" : "New rule"}</div>
                {isDirty && <span className="text-[11px] px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200">Unsaved</span>}
              </div>
              <div className="text-xs text-slate-500 mt-0.5">Build your automation in 3 quick steps.</div>
            </div>
            <button className="px-2 py-1 border rounded-lg text-sm hover:bg-slate-50" onClick={requestClose} disabled={saving}>✕</button>
          </div>

          <div className="mt-3 grid grid-cols-3 gap-2">
            {steps.map((s) => {
              const active = step === s.id;
              const done = step > s.id;
              return (
                <button
                  key={`step:${s.id}`}
                  type="button"
                  onClick={() => setStep(s.id)}
                  className={`text-left px-3 py-2 rounded-xl border transition ${
                    active ? "bg-indigo-50 border-indigo-200" : (done ? "bg-emerald-50 border-emerald-200" : "bg-white hover:bg-slate-50")
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium">{s.id}. {s.label}</div>
                    {done ? <span className="text-xs text-emerald-700">Done</span> : <span className="text-xs text-slate-500">{active ? "Current" : ""}</span>}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">{s.hint}</div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="p-4 max-h-[74vh] overflow-y-auto">
          {step === 1 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <div className="text-xs text-slate-500 mb-1">Name</div>
                <input
                  className={`w-full border rounded-lg px-3 py-2 ${nameTouched && !String(draft.name || "").trim() ? "border-rose-300 bg-rose-50" : ""}`}
                  value={draft.name}
                  onChange={(e) => onChange({ name: e.target.value })}
                  onBlur={() => setNameTouched(true)}
                  placeholder="e.g. Order confirmation (Delivery statuses)"
                />
                {nameTouched && !String(draft.name || "").trim() && (
                  <div className="text-[11px] text-rose-700 mt-1">Name is required.</div>
                )}
              </div>

              <div className="md:col-span-2">
                <div className="text-xs text-slate-500 mb-1">Workspaces</div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className={`px-3 py-2 border rounded-lg text-sm ${String(draft.workspaceScope || 'current') === 'current' ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`}
                    onClick={() => onChange({ workspaceScope: 'current', workspaces: [] })}
                    title="Only run this automation in the currently selected workspace"
                  >
                    Current only ({String(currentWorkspace || 'irranova').toUpperCase()})
                  </button>
                  <button
                    type="button"
                    className={`px-3 py-2 border rounded-lg text-sm ${String(draft.workspaceScope || '') === 'all' ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`}
                    onClick={() => onChange({ workspaceScope: 'all', workspaces: ['*'] })}
                    title="Run in all workspaces"
                  >
                    All workspaces
                  </button>
                  <button
                    type="button"
                    className={`px-3 py-2 border rounded-lg text-sm ${String(draft.workspaceScope || '') === 'selected' ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`}
                    onClick={() => {
                      const ws = String(currentWorkspace || 'irranova').trim().toLowerCase();
                      const list = Array.isArray(draft.workspaces) ? draft.workspaces : [];
                      const next = list.length ? list : [ws];
                      onChange({ workspaceScope: 'selected', workspaces: next });
                    }}
                    title="Pick specific workspaces"
                  >
                    Selected…
                  </button>
                </div>
                {String(draft.workspaceScope || '') === 'selected' && (
                  <div className="mt-2 border rounded-xl p-3 bg-slate-50">
                    <div className="text-[11px] text-slate-500 mb-2">Select workspaces this rule should run on:</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {(Array.isArray(workspaceOptions) && workspaceOptions.length ? workspaceOptions : [{ id: 'irranova', label: 'IRRANOVA' }, { id: 'irrakids', label: 'IRRAKIDS' }]).map((w) => {
                        const id = String(w?.id || '').trim().toLowerCase();
                        if (!id) return null;
                        const checked = Array.isArray(draft.workspaces) && draft.workspaces.map((x)=>String(x||'').trim().toLowerCase()).includes(id);
                        return (
                          <label key={`ws-scope:${id}`} className="flex items-center gap-2 text-sm">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={(e) => {
                                const prev = Array.isArray(draft.workspaces) ? draft.workspaces.map((x)=>String(x||'').trim().toLowerCase()).filter(Boolean) : [];
                                const next = e.target.checked ? Array.from(new Set([...prev, id])) : prev.filter((x) => x !== id);
                                onChange({ workspaces: next });
                              }}
                            />
                            <span className="truncate">{String(w?.label || id)}</span>
                          </label>
                        );
                      })}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-2">
                      If none selected, it will default to current workspace.
                    </div>
                  </div>
                )}
              </div>

              <div className="md:col-span-2">
                <div className="text-xs text-slate-500 mb-1">Trigger</div>
                <div className="flex flex-wrap gap-2">
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.triggerSource === "whatsapp" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ triggerSource: "whatsapp" })}>
                    WhatsApp incoming
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.triggerSource === "shopify" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ triggerSource: "shopify" })}>
                    Shopify webhook
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.triggerSource === "delivery" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ triggerSource: "delivery" })}>
                    Delivery status
                  </button>
                </div>

                {draft.triggerSource === "whatsapp" && (
                  <div className="mt-3 border rounded-xl p-3 bg-slate-50">
                    <div className="text-xs font-semibold text-slate-700 mb-2">WhatsApp settings</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Trigger type</div>
                        <select
                          className="w-full border rounded-lg px-3 py-2"
                          value={String(draft.waTriggerMode || "incoming")}
                          onChange={(e) => onChange({ waTriggerMode: e.target.value })}
                        >
                          <option value="incoming">Incoming message</option>
                          <option value="button">Button/list click</option>
                          <option value="no_reply">No reply after time</option>
                        </select>
                        <div className="text-[11px] text-slate-500 mt-1">
                          Use <span className="font-mono">Incoming message</span> for keyword auto-replies, <span className="font-mono">Button click</span> for interactive flows, or <span className="font-mono">No reply</span> to follow up when the customer is waiting.
                        </div>
                      </div>

                      {String(draft.waTriggerMode || "incoming") === "button" && (
                        <div>
                          <div className="text-xs text-slate-500 mb-1">Button IDs (one per line)</div>
                          <textarea
                            className="w-full border rounded-lg px-3 py-2 font-mono text-xs"
                            rows={3}
                            value={draft.buttonIds || ""}
                            onChange={(e) => onChange({ buttonIds: e.target.value })}
                            placeholder={"buy_item\norder_status\ngender_girls"}
                          />
                          <div className="text-[11px] text-slate-500 mt-1">
                            Match by <span className="font-mono">interactive.id</span> (recommended). These IDs come from your buttons/list rows.
                          </div>
                        </div>
                      )}

                      {String(draft.waTriggerMode || "incoming") === "no_reply" && (
                        <div>
                          <div className="text-xs text-slate-500 mb-1">Wait (minutes)</div>
                          <input
                            type="number"
                            min={1}
                            className="w-full border rounded-lg px-3 py-2"
                            value={Number(draft.noReplyMinutes || 30)}
                            onChange={(e) => onChange({ noReplyMinutes: Number(e.target.value || 0) })}
                          />
                          <div className="text-[11px] text-slate-500 mt-1">
                            After a customer message, if nobody replies within this time, the rule will run once.
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Test phone numbers (optional)</div>
                        <textarea
                          className="w-full border rounded-lg px-3 py-2 font-mono text-xs"
                          rows={3}
                          value={draft.whatsappTestPhones || ""}
                          onChange={(e) => onChange({ whatsappTestPhones: e.target.value })}
                          placeholder={"+212612345678\n+212600000000"}
                        />
                        <div className="text-[11px] text-slate-500 mt-1">
                          If set, this rule only fires for these numbers (digits-only match).
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Special condition (optional)</div>
                        <label className="text-xs text-slate-700 flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={!!draft.waNoUrlNoDigit}
                            onChange={(e) => onChange({ waNoUrlNoDigit: !!e.target.checked })}
                            disabled={String(draft.waTriggerMode || "incoming") !== "incoming"}
                          />
                          Only when message has no URL and no digits (menu-style)
                        </label>
                        <div className="text-[11px] text-slate-500 mt-1">
                          This is used for “choose an option” style menus. It only applies to <span className="font-mono">Incoming message</span>.
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {draft.triggerSource === "shopify" && (
                  <div className="mt-3 border rounded-xl p-3 bg-slate-50">
                    <div className="text-xs font-semibold text-slate-700 mb-2">Shopify settings</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Shopify topic</div>
                        <select
                          className="w-full border rounded-lg px-3 py-2"
                          value={draft.shopifyTopicPreset || draft.shopifyTopic || "orders/paid"}
                          onChange={(e) => {
                            const v = e.target.value;
                            onChange({ shopifyTopicPreset: v, shopifyTopicCustom: "", shopifyTopic: v });
                          }}
                        >
                          {shopifyTopics.map((x) => <option key={x.topic} value={x.topic}>{x.label}</option>)}
                        </select>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Custom topic (optional)</div>
                        <input
                          className="w-full border rounded-lg px-3 py-2 font-mono text-xs"
                          value={draft.shopifyTopicCustom || ""}
                          onChange={(e) => {
                            const custom = e.target.value;
                            const preset = String(draft.shopifyTopicPreset || draft.shopifyTopic || "orders/paid");
                            onChange({ shopifyTopicCustom: custom, shopifyTopic: String(custom || "").trim() ? custom : preset });
                          }}
                          placeholder="orders/create"
                        />
                      </div>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-2">
                      Use the same webhook URL for all topics: <span className="font-mono">/shopify/webhook/{'{workspace}'}</span>
                    </div>

                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Tagged with (optional)</div>
                        <input
                          className="w-full border rounded-lg px-3 py-2"
                          value={draft.shopifyTaggedWith || ""}
                          onChange={(e) => onChange({ shopifyTaggedWith: e.target.value })}
                          placeholder="e.g. vip"
                        />
                        <div className="text-[11px] text-slate-500 mt-1">
                          If set, this rule only fires when the Shopify order <span className="font-mono">tags</span> contains this value.
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Test phone numbers (optional)</div>
                        <textarea
                          className="w-full border rounded-lg px-3 py-2 font-mono text-xs"
                          rows={3}
                          value={draft.shopifyTestPhones || ""}
                          onChange={(e) => onChange({ shopifyTestPhones: e.target.value })}
                          placeholder={"+212612345678\n+212600000000"}
                        />
                        <div className="text-[11px] text-slate-500 mt-1">
                          If set, this rule only fires when the Shopify payload phone matches one of these numbers.
                        </div>
                      </div>
                    </div>
                    <div className="mt-3">
                      <div className="text-xs text-slate-500 mb-1">Add tag after WhatsApp send succeeds (optional)</div>
                      <input
                        className="w-full border rounded-lg px-3 py-2"
                        value={draft.shopifyTagOnSent || ""}
                        onChange={(e) => onChange({ shopifyTagOnSent: e.target.value })}
                        placeholder="e.g. whatsapp_sent"
                      />
                      <div className="text-[11px] text-slate-500 mt-1">
                        If set, the app will add this tag to the Shopify order after the WhatsApp message is sent successfully.
                      </div>
                    </div>
                  </div>
                )}

                {draft.triggerSource === "delivery" && (
                  <div className="mt-3 border rounded-xl p-3 bg-slate-50">
                    <div className="text-xs font-semibold text-slate-700 mb-2">Delivery settings</div>
                    <div className="text-xs text-slate-500 mb-1">Delivery event</div>
                    <div className="w-full border rounded-lg px-3 py-2 bg-white text-sm">
                      Order status changed <span className="font-mono text-xs">(order_status_changed)</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      The delivery app posts one webhook per status change. Choose which statuses should trigger WhatsApp.
                    </div>

                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
                      <MultiSelectDropdown
                        label="Statuses (optional)"
                        options={deliveryStatusOptions || []}
                        selected={deliverySelected}
                        placeholder="All statuses"
                        onChange={(arr) => onChange({ deliveryStatuses: (Array.isArray(arr) ? arr : []).join(", ") })}
                      />
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Test phone numbers (optional)</div>
                        <textarea
                          className="w-full border rounded-lg px-3 py-2 font-mono text-xs"
                          rows={3}
                          value={draft.deliveryTestPhones || ""}
                          onChange={(e) => onChange({ deliveryTestPhones: e.target.value })}
                          placeholder={"+212612345678\n+212600000000"}
                        />
                        <div className="text-[11px] text-slate-500 mt-1">
                          If set, this rule only fires when the delivery order phone matches one of these numbers.
                        </div>
                      </div>
                    </div>

                    <div className="mt-3">
                      <div className="text-xs text-slate-500 mb-1">Delivery variables (click to copy)</div>
                      <div className="flex flex-wrap gap-1">
                        {DELIVERY_VARS.map((v) => (
                          <button
                            key={`delvar:${v}`}
                            type="button"
                            className="px-2 py-0.5 rounded border text-xs hover:bg-white"
                            onClick={() => copyVar(v)}
                          >
                            {v}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <div className="text-xs text-slate-500 mb-1">Send to (WhatsApp number)</div>
                <input className="w-full border rounded-lg px-3 py-2 font-mono text-xs" value={draft.to || "{{ phone }}"} onChange={(e) => onChange({ to: e.target.value })} />
                <div className="text-[11px] text-slate-500 mt-1">
                  Use <span className="font-mono">{"{{ phone }}"}</span> (works for WhatsApp + Shopify + Delivery triggers).
                </div>
              </div>

              <div>
                <div className="text-xs text-slate-500 mb-1">Keywords (comma separated)</div>
                <input className="w-full border rounded-lg px-3 py-2" value={draft.keywords} onChange={(e) => onChange({ keywords: e.target.value })} placeholder="price, livraison, سومة" />
                <div className="text-[11px] text-slate-500 mt-1">If empty, it will match all incoming messages.</div>
              </div>
              <div>
                <div className="text-xs text-slate-500 mb-1">Cooldown (seconds)</div>
                <input type="number" className="w-full border rounded-lg px-3 py-2" value={draft.cooldownSeconds} onChange={(e) => onChange({ cooldownSeconds: Number(e.target.value || 0) })} />
                <div className="text-[11px] text-slate-500 mt-1">Prevents spam replies to the same user.</div>
              </div>

              <div className="md:col-span-2">
                <div className="text-xs text-slate-500 mb-1">Action type</div>
                <div className="flex flex-wrap gap-2 mb-2">
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.actionMode !== "template" && draft.actionMode !== "order_confirm" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ actionMode: "text" })}>
                    Text
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.actionMode === "template" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ actionMode: "template" })}>
                    WhatsApp Template
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.actionMode === "order_confirm" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ actionMode: "order_confirm" })}>
                    Confirmation flow
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.actionMode === "buttons" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ actionMode: "buttons" })}>
                    Buttons
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.actionMode === "list" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ actionMode: "list" })}>
                    List
                  </button>
                  <button className={`px-3 py-2 border rounded-lg text-sm ${draft.actionMode === "order_status" ? "bg-indigo-50 border-indigo-200" : "hover:bg-slate-50"}`} onClick={() => onChange({ actionMode: "order_status" })}>
                    Order status lookup
                  </button>
                </div>

                {(draft.actionMode === "template" || draft.actionMode === "order_confirm") ? (
                  <div className="border rounded-xl p-3 bg-slate-50">
                    {templatesError && <div className="p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{templatesError}</div>}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Template</div>
                        <select
                          className="w-full border rounded-lg px-3 py-2"
                          value={draft.templateName || ""}
                          onChange={(e) => {
                            const name = e.target.value;
                            const tpl = approvedTemplates.find((t) => t.name === name) || null;
                            const n = inferBodyVarCount(tpl);
                            const btnTexts = (() => {
                              try {
                                const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                                const buttons = comps.find((c) => String(c?.type || "").toUpperCase() === "BUTTONS") || null;
                                const arr = Array.isArray(buttons?.buttons) ? buttons.buttons : [];
                                return arr
                                  .map((b) => String(b?.text || b?.title || b?.url || "").trim())
                                  .filter(Boolean);
                              } catch {
                                return [];
                              }
                            })();
                            const headerFormat = (() => {
                              try {
                                const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                                const h = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
                                return String(h?.format || "").toUpperCase();
                              } catch {
                                return "";
                              }
                            })();
                            const shouldAutoFillBranches =
                              String(draft.actionMode || "") === "order_confirm" &&
                              String(draft.ocConfirmTitles || "").trim() === DEFAULT_OC_CONFIRM_TITLES &&
                              String(draft.ocChangeTitles || "").trim() === DEFAULT_OC_CHANGE_TITLES &&
                              String(draft.ocTalkTitles || "").trim() === DEFAULT_OC_TALK_TITLES;
                            onChange({
                              templateName: name,
                              templateLanguage: String(tpl?.language || draft.templateLanguage || "en"),
                              templateVars: Array.from({ length: n }, (_, i) => (draft.templateVars?.[i] || "")),
                              templateHeaderUrl: (["IMAGE", "VIDEO", "DOCUMENT"].includes(headerFormat) ? (draft.templateHeaderUrl || "") : ""),
                              ...(shouldAutoFillBranches ? {
                                ocConfirmTitles: String(btnTexts?.[0] || ""),
                                ocChangeTitles: String(btnTexts?.[1] || ""),
                                ocTalkTitles: String(btnTexts?.[2] || ""),
                              } : {}),
                            });
                          }}
                          disabled={templatesLoading}
                        >
                          <option value="">{templatesLoading ? "Loading…" : "Select template…"}</option>
                          {approvedTemplates.map((t) => (
                            <option key={`${t.name}:${t.language}`} value={t.name}>{t.name} ({t.language})</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Language</div>
                        <input className="w-full border rounded-lg px-3 py-2 font-mono text-xs" value={draft.templateLanguage || "en"} onChange={(e) => onChange({ templateLanguage: e.target.value })} />
                      </div>
                    </div>

                    {(() => {
                      try {
                        const tn = String(draft.templateName || "").trim();
                        if (!tn) return null;
                        const tpl = approvedTemplates.find((t) => t.name === tn) || null;
                        const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                        const h = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
                        const fmt = String(h?.format || "").toUpperCase();
                        if (!["IMAGE", "VIDEO", "DOCUMENT"].includes(fmt)) return null;
                        return (
                          <div className="mt-2">
                            <div className="text-xs text-slate-500 mb-1">Header {fmt} URL</div>
                            <input
                              className="w-full border rounded-lg px-3 py-2 font-mono text-xs"
                              value={draft.templateHeaderUrl || ""}
                              onChange={(e) => onChange({ templateHeaderUrl: e.target.value })}
                              placeholder="https://... (public image/video/pdf URL)"
                            />
                            <div className="mt-2">
                              <SingleSelectDropdown
                                label="Or select a variable"
                                options={availableVarOptions}
                                value=""
                                placeholder="Choose variable…"
                                onChange={(v) => {
                                  const vv = String(v || "").trim();
                                  if (!vv) return;
                                  onChange({ templateHeaderUrl: `{{ ${vv} }}` });
                                }}
                              />
                            </div>
                            {draft.triggerSource !== "shopify" && draft.triggerSource !== "delivery" && (
                              <div className="text-[11px] text-amber-700 mt-2">
                                Note: Shopify variables only have values when the trigger is <b>Shopify webhook</b>. For WhatsApp triggers, only <span className="font-mono">{"{{ phone }}"}</span> and <span className="font-mono">{"{{ text }}"}</span> are populated.
                              </div>
                            )}
                            <div className="text-[11px] text-slate-500 mt-1">
                              This template requires a {fmt} header. If you leave it empty, WhatsApp will reject the message (error 132012).
                            </div>
                          </div>
                        );
                      } catch {
                        return null;
                      }
                    })()}

                    {selectedTemplatePreview && (
                      <div className="mt-3 border rounded-xl p-3 bg-white">
                        <div className="text-xs font-semibold text-slate-700">Template preview</div>
                        {selectedTemplatePreview.headerFormat && (
                          <div className="text-[11px] text-slate-500 mt-1">
                            Header: <span className="font-mono">{selectedTemplatePreview.headerFormat}</span>
                          </div>
                        )}
                        {selectedTemplatePreview.bodyText && (
                          <div className="mt-2">
                            <div className="text-[11px] text-slate-500 mb-1">Body</div>
                            <div className="whitespace-pre-wrap text-sm border rounded-lg p-2 bg-slate-50">{selectedTemplatePreview.bodyText}</div>
                          </div>
                        )}
                        {selectedTemplatePreview.placeholders?.length > 0 && (
                          <div className="mt-2 text-[11px] text-slate-600">
                            Placeholders in body:{" "}
                            <span className="font-mono">
                              {selectedTemplatePreview.placeholders.map((n) => `{{${n}}}`).join(", ")}
                            </span>
                          </div>
                        )}
                        {selectedTemplatePreview.footerText && (
                          <div className="mt-2 text-[11px] text-slate-500">
                            Footer: <span className="whitespace-pre-wrap">{selectedTemplatePreview.footerText}</span>
                          </div>
                        )}
                        {Array.isArray(selectedTemplatePreview.buttons) && selectedTemplatePreview.buttons.length > 0 && (
                          <div className="mt-2">
                            <div className="text-[11px] text-slate-500 mb-1">Buttons</div>
                            <div className="flex flex-wrap gap-2">
                              {selectedTemplatePreview.buttons.map((b, i) => (
                                <span key={`tplbtn:${i}`} className="px-2 py-1 rounded border text-xs bg-white">
                                  {String(b?.text || b?.title || b?.url || b?.type || "button")}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {draft.actionMode === "order_confirm" && draft.triggerSource === "shopify" && (
                      <div className="mt-3 border rounded-xl p-3 bg-white">
                        <div className="text-xs font-semibold text-slate-700">Order entry gate (optional)</div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          Use this if you want the confirmation flow to run only for specific Shopify orders.
                        </div>
                        <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2">
                          <div>
                            <div className="text-xs text-slate-500 mb-1">Mode</div>
                            <select
                              className="w-full border rounded-lg px-3 py-2"
                              value={String(draft.ocEntryGateMode || "all")}
                              onChange={(e) => onChange({ ocEntryGateMode: e.target.value })}
                            >
                              <option value="all">All orders (no gate)</option>
                              <option value="tag_or_online_store">Required tag OR Online Store order</option>
                            </select>
                          </div>
                          <div>
                            <div className="text-xs text-slate-500 mb-1">Required tag</div>
                            <input
                              className="w-full border rounded-lg px-3 py-2"
                              value={String(draft.ocRequiredTag || "")}
                              onChange={(e) => onChange({ ocRequiredTag: e.target.value })}
                              placeholder="easysell_cod_form"
                              disabled={String(draft.ocEntryGateMode || "all") === "all"}
                            />
                          </div>
                        </div>
                        <div className="mt-2">
                          <label className="text-sm flex items-center gap-2">
                            <input
                              type="checkbox"
                              checked={!!draft.ocIncludeOnlineStore}
                              onChange={(e) => onChange({ ocIncludeOnlineStore: e.target.checked })}
                              disabled={String(draft.ocEntryGateMode || "all") === "all"}
                            />
                            Also allow Online Store orders (source_name = web)
                          </label>
                        </div>
                      </div>
                    )}

                    {(Array.isArray(draft.templateVars) && draft.templateVars.length > 0) && (
                      <div className="mt-3">
                        <div className="text-xs text-slate-500 mb-1">Body variables</div>
                        {(() => {
                          return (
                            <div className="mb-2">
                              <SingleSelectDropdown
                                label="Select a variable to insert"
                                options={availableVarOptions}
                                value=""
                                placeholder="Choose variable…"
                                onChange={(v) => {
                                  const vv = String(v || "").trim();
                                  if (!vv) return;
                                  try { copyVar(vv); } catch {}
                                }}
                              />
                              <div className="text-[11px] text-slate-500 mt-1">
                                Tip: select a variable to copy it, then paste into any Var field below.
                              </div>
                            </div>
                          );
                        })()}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {draft.templateVars.map((v, idx) => (
                            <div key={`tplvarwrap:${idx}`} className="grid grid-cols-1 gap-2">
                              <input
                                className="w-full border rounded-lg px-3 py-2"
                                placeholder={`Var ${idx + 1} (e.g. {{ order_number }})`}
                                value={v}
                                onChange={(e) => {
                                  const next = [...draft.templateVars];
                                  next[idx] = e.target.value;
                                  onChange({ templateVars: next });
                                }}
                              />
                              <SingleSelectDropdown
                                label={`Pick var for {{${idx + 1}}}`}
                                options={availableVarOptions}
                                value=""
                                placeholder="Choose…"
                                onChange={(sel) => {
                                  const vv = String(sel || "").trim();
                                  if (!vv) return;
                                  const next = [...draft.templateVars];
                                  next[idx] = `{{ ${vv} }}`;
                                  onChange({ templateVars: next });
                                }}
                              />
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (draft.actionMode === "buttons" ? (
                  <div className="border rounded-xl p-3 bg-slate-50 space-y-3">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Buttons body text</div>
                      <textarea className="w-full border rounded-lg px-3 py-2" rows={4} value={draft.buttonsText || ""} onChange={(e) => onChange({ buttonsText: e.target.value })} placeholder="Veuillez choisir une option…" />
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Buttons (one per line: id|title)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={4} value={draft.buttonsLines || ""} onChange={(e) => onChange({ buttonsLines: e.target.value })} placeholder={"buy_item|Acheter | شراء\norder_status|Statut | حالة"} />
                      <div className="text-[11px] text-slate-500 mt-1">
                        Prefer matching by button <span className="font-mono">id</span> (stable). WhatsApp truncates long titles.
                      </div>
                    </div>
                  </div>
                ) : (draft.actionMode === "list" ? (
                  <div className="border rounded-xl p-3 bg-slate-50 space-y-3">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">List body text</div>
                      <textarea className="w-full border rounded-lg px-3 py-2" rows={3} value={draft.listText || ""} onChange={(e) => onChange({ listText: e.target.value })} placeholder="Veuillez choisir: Fille ou Garçon…" />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">List button label</div>
                        <input className="w-full border rounded-lg px-3 py-2" value={draft.listButtonText || ""} onChange={(e) => onChange({ listButtonText: e.target.value })} placeholder="Choisir | اختر" />
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Section title</div>
                        <input className="w-full border rounded-lg px-3 py-2" value={draft.listSectionTitle || ""} onChange={(e) => onChange({ listSectionTitle: e.target.value })} placeholder="Genre | النوع" />
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Rows (one per line: id|title|description optional)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={4} value={draft.listRowsLines || ""} onChange={(e) => onChange({ listRowsLines: e.target.value })} placeholder={"gender_girls|Fille | بنت\ngender_boys|Garçon | ولد"} />
                    </div>
                  </div>
                ) : (draft.actionMode === "order_status" ? (
                  <div className="border rounded-xl p-3 bg-slate-50">
                    <div className="text-xs text-slate-500 mb-1">Order status lookup</div>
                    <div className="text-sm text-slate-700">
                      This action queries Shopify for recent orders by the customer phone and sends a bilingual status summary.
                    </div>
                    <div className="text-[11px] text-slate-500 mt-2">
                      Tip: use a WhatsApp <span className="font-mono">Button/list click</span> trigger and match <span className="font-mono">order_status</span>.
                    </div>
                  </div>
                ) : (
                  <div className="border rounded-xl p-3 bg-slate-50">
                    <div className="text-xs text-slate-500 mb-1">Auto-reply text</div>
                    <textarea className="w-full border rounded-lg px-3 py-2" rows={5} value={draft.replyText} onChange={(e) => onChange({ replyText: e.target.value })} placeholder="Type the WhatsApp message to send…" />
                    <div className="text-[11px] text-slate-500 mt-1">
                      Variables: <span className="font-mono">{"{{ phone }}"}</span>, <span className="font-mono">{"{{ text }}"}</span>, <span className="font-mono">{"{{ order_number }}"}</span>
                    </div>
                  </div>
                )))))}
              </div>

              <div className="md:col-span-2">
                <div className="text-xs text-slate-500 mb-1">Optional tag to add</div>
                <input className="w-full border rounded-lg px-3 py-2" value={draft.tag} onChange={(e) => onChange({ tag: e.target.value })} placeholder="e.g. Auto" />
              </div>
              <div className="md:col-span-2">
                <label className="text-sm flex items-center gap-2">
                  <input type="checkbox" checked={!!draft.enabled} onChange={(e) => onChange({ enabled: e.target.checked })} />
                  Enabled
                </label>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4">
              {draft.actionMode !== "order_confirm" ? (
                <div className="border rounded-xl p-4 bg-slate-50">
                  <div className="font-semibold">Button click branches</div>
                  <div className="text-sm text-slate-600 mt-1">
                    Branches are used in the <span className="font-medium">Confirmation flow</span> because template button labels can differ per template.
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="px-3 py-2 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700"
                      onClick={() => onChange({ actionMode: "order_confirm" })}
                    >
                      Switch to Confirmation flow
                    </button>
                    <button
                      type="button"
                      className="px-3 py-2 rounded-lg border hover:bg-white"
                      onClick={() => setStep(2)}
                    >
                      Back to Actions
                    </button>
                  </div>
                </div>
              ) : (
                <div className="border rounded-xl p-4 bg-white">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-semibold">Button click branches</div>
                      <div className="text-sm text-slate-600 mt-1">
                        Add all possible button texts/labels here (different templates can have different button text). Matching by button <span className="font-mono text-xs">id</span> is optional.
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="md:col-span-2 border rounded-xl p-3 bg-slate-50">
                      <div className="text-xs font-semibold text-slate-700">Template buttons</div>
                      <div className="text-[11px] text-slate-500 mt-1">
                        If your template has buttons, you can auto-fill Button 1/2/3 from them.
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {Array.isArray(selectedTemplatePreview?.buttons) && selectedTemplatePreview.buttons.length > 0 ? (
                          selectedTemplatePreview.buttons.map((b, i) => (
                            <span key={`tplbtn_branch:${i}`} className="px-2 py-1 rounded border text-xs bg-white">
                              {String(b?.text || b?.title || b?.url || b?.type || "button")}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-slate-500">No buttons detected for the selected template.</span>
                        )}
                      </div>
                      {Array.isArray(selectedTemplatePreview?.buttons) && selectedTemplatePreview.buttons.length > 0 && (
                        <div className="mt-2">
                          <button
                            type="button"
                            className="px-3 py-2 rounded-lg border bg-white hover:bg-slate-50 text-sm"
                            onClick={() => {
                              const btns = selectedTemplatePreview.buttons
                                .map((b) => String(b?.text || b?.title || b?.url || "").trim())
                                .filter(Boolean);
                              onChange({
                                ocConfirmTitles: String(btns?.[0] || ""),
                                ocChangeTitles: String(btns?.[1] || ""),
                                ocTalkTitles: String(btns?.[2] || ""),
                              });
                            }}
                          >
                            Auto-fill from template buttons
                          </button>
                        </div>
                      )}
                    </div>
                    <div className="md:col-span-2">
                      <div className="text-xs text-slate-500 mb-1">Button 1 titles (one per line)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={2} value={draft.ocConfirmTitles || ""} onChange={(e)=>onChange({ ocConfirmTitles: e.target.value })} />
                    </div>
                    <div className="md:col-span-2">
                      <div className="text-xs text-slate-500 mb-1">Button 2 titles (one per line)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={2} value={draft.ocChangeTitles || ""} onChange={(e)=>onChange({ ocChangeTitles: e.target.value })} />
                    </div>
                    <div className="md:col-span-2">
                      <div className="text-xs text-slate-500 mb-1">Button 3 titles (one per line)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={2} value={draft.ocTalkTitles || ""} onChange={(e)=>onChange({ ocTalkTitles: e.target.value })} />
                    </div>

                    <div>
                      <div className="text-xs text-slate-500 mb-1">Button 1 IDs (optional)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={2} value={draft.ocConfirmIds || ""} onChange={(e)=>onChange({ ocConfirmIds: e.target.value })} />
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Button 2 IDs (optional)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={2} value={draft.ocChangeIds || ""} onChange={(e)=>onChange({ ocChangeIds: e.target.value })} />
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Button 3 IDs (optional)</div>
                      <textarea className="w-full border rounded-lg px-3 py-2 font-mono text-xs" rows={2} value={draft.ocTalkIds || ""} onChange={(e)=>onChange({ ocTalkIds: e.target.value })} />
                    </div>

                    <div className="md:col-span-2">
                      <div className="text-xs text-slate-500 mb-1">Button 1 audio URL (optional)</div>
                      <input className="w-full border rounded-lg px-3 py-2 font-mono text-xs" value={draft.ocConfirmAudioUrl || ""} onChange={(e)=>onChange({ ocConfirmAudioUrl: e.target.value })} placeholder="https://.../confirm.ogg" />
                    </div>
                    <div className="md:col-span-2">
                      <div className="text-xs text-slate-500 mb-1">Button 2 audio URL (optional)</div>
                      <input className="w-full border rounded-lg px-3 py-2 font-mono text-xs" value={draft.ocChangeAudioUrl || ""} onChange={(e)=>onChange({ ocChangeAudioUrl: e.target.value })} placeholder="https://.../change.ogg" />
                    </div>
                    <div className="md:col-span-2">
                      <div className="text-xs text-slate-500 mb-1">Button 3 audio URL (optional)</div>
                      <input className="w-full border rounded-lg px-3 py-2 font-mono text-xs" value={draft.ocTalkAudioUrl || ""} onChange={(e)=>onChange({ ocTalkAudioUrl: e.target.value })} placeholder="https://.../talk.ogg" />
                    </div>

                    <div className="md:col-span-2 flex items-center justify-between gap-3 border rounded-xl p-3 bg-slate-50">
                      <label className="text-sm flex items-center gap-2">
                        <input type="checkbox" checked={!!draft.ocSendItems} onChange={(e)=>onChange({ ocSendItems: e.target.checked })} />
                        Send ordered items after Button 1 (catalog items)
                      </label>
                      <div className="flex items-center gap-2">
                        <div className="text-xs text-slate-500">Max items</div>
                        <input type="number" className="w-24 border rounded-lg px-3 py-2" value={draft.ocMaxItems || 10} onChange={(e)=>onChange({ ocMaxItems: Number(e.target.value || 10) })} />
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="px-4 py-3 border-t bg-white flex items-center justify-between gap-2">
          <button className="px-3 py-2 border rounded-lg text-sm hover:bg-slate-50" onClick={requestClose} disabled={saving}>Cancel</button>
          <div className="flex items-center gap-2">
            <button className="px-3 py-2 border rounded-lg text-sm hover:bg-slate-50" onClick={onBack} disabled={saving || step === 1}>Back</button>
            {step < 3 ? (
              <button className="px-3 py-2 rounded-lg text-sm bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60" onClick={onNext} disabled={saving || !canGoNext()}>
                Next
              </button>
            ) : (
              <button className="px-3 py-2 rounded-lg text-sm bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60" onClick={onSave} disabled={saving || !canSave}>
                {saving ? "Saving…" : "Save rule"}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/*
  Legacy RuleEditor UI removed in favor of 3-step wizard.
*/

/*
            {draft.triggerSource === "shopify" && (
              <div className="mt-2">
                <div className="text-xs text-slate-500 mb-1">Shopify topic</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <select className="w-full border rounded px-2 py-1" value={draft.shopifyTopic || "orders/paid"} onChange={(e) => onChange({ shopifyTopic: e.target.value })}>
                    {shopifyTopics.map((x) => <option key={x.topic} value={x.topic}>{x.label}</option>)}
                  </select>
                  <input
                    className="w-full border rounded px-2 py-1 font-mono text-xs"
                    value={draft.shopifyTopic || ""}
                    onChange={(e) => onChange({ shopifyTopic: e.target.value })}
                    placeholder="Custom topic (optional)"
                  />
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Use the SAME webhook URL for all Shopify topics (Shopify creates one subscription per topic, but the URL can be identical):
                  <span className="font-mono"> /shopify/webhook/{'{workspace}'}</span>
                </div>

                <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Tagged with (optional)</div>
                    <input
                      className="w-full border rounded px-2 py-1"
                      value={draft.shopifyTaggedWith || ""}
                      onChange={(e) => onChange({ shopifyTaggedWith: e.target.value })}
                      placeholder="e.g. vip"
                    />
                    <div className="text-[11px] text-slate-500 mt-1">
                      Uses <span className="font-mono">orders/updated</span> + condition <span className="font-mono">tag_contains</span>.
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Test phone numbers (optional)</div>
                    <textarea
                      className="w-full border rounded px-2 py-1 font-mono text-xs"
                      rows={3}
                      value={draft.shopifyTestPhones || ""}
                      onChange={(e) => onChange({ shopifyTestPhones: e.target.value })}
                      placeholder={"+212612345678\n+212600000000"}
                    />
                    <div className="text-[11px] text-slate-500 mt-1">
                      If set, this rule only fires when the Shopify payload phone matches one of these numbers.
                    </div>
                  </div>
                </div>

              </div>
            )}
          </div>

          <div className="md:col-span-2">
            <div className="text-xs text-slate-500 mb-1">Send to (WhatsApp number)</div>
            <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={draft.to || "{{ phone }}"} onChange={(e) => onChange({ to: e.target.value })} />
            <div className="text-[11px] text-slate-500 mt-1">
              Use <span className="font-mono">{"{{ phone }}"}</span> (works for WhatsApp + Shopify + Delivery triggers).
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500 mb-1">Keywords (comma separated)</div>
            <input className="w-full border rounded px-2 py-1" value={draft.keywords} onChange={(e) => onChange({ keywords: e.target.value })} placeholder="price, livraison, سومة" />
            <div className="text-[11px] text-slate-500 mt-1">If empty, it will match all incoming messages.</div>
          </div>
          <div>
            <div className="text-xs text-slate-500 mb-1">Cooldown (seconds)</div>
            <input type="number" className="w-full border rounded px-2 py-1" value={draft.cooldownSeconds} onChange={(e) => onChange({ cooldownSeconds: Number(e.target.value || 0) })} />
            <div className="text-[11px] text-slate-500 mt-1">Prevents spam replies to the same user.</div>
          </div>
          <div className="md:col-span-2">
            <div className="text-xs text-slate-500 mb-1">Action</div>
            <div className="flex gap-2 mb-2">
              <button className={`px-2 py-1 border rounded text-sm ${draft.actionMode !== "template" ? "bg-blue-50 border-blue-200" : ""}`} onClick={() => onChange({ actionMode: "text" })}>
                Text
              </button>
              <button className={`px-2 py-1 border rounded text-sm ${draft.actionMode === "template" ? "bg-blue-50 border-blue-200" : ""}`} onClick={() => onChange({ actionMode: "template" })}>
                WhatsApp Template
              </button>
              <button className={`px-2 py-1 border rounded text-sm ${draft.actionMode === "order_confirm" ? "bg-blue-50 border-blue-200" : ""}`} onClick={() => onChange({ actionMode: "order_confirm" })}>
                Confirmation flow
              </button>
            </div>

            {(draft.actionMode === "template" || draft.actionMode === "order_confirm") ? (
              <div className="space-y-2">
                {templatesError && <div className="p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{templatesError}</div>}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Template</div>
                    <select
                      className="w-full border rounded px-2 py-1"
                      value={draft.templateName || ""}
                      onChange={(e) => {
                        const name = e.target.value;
                        const tpl = approvedTemplates.find((t) => t.name === name) || null;
                        const n = inferBodyVarCount(tpl);
                        const headerFormat = (() => {
                          try {
                            const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                            const h = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
                            return String(h?.format || "").toUpperCase();
                          } catch {
                            return "";
                          }
                        })();
                        onChange({
                          templateName: name,
                          templateLanguage: String(tpl?.language || draft.templateLanguage || "en"),
                          templateVars: Array.from({ length: n }, (_, i) => (draft.templateVars?.[i] || "")),
                          // If switching to a new template, keep existing header URL only if it still needs a media header.
                          templateHeaderUrl: (["IMAGE", "VIDEO", "DOCUMENT"].includes(headerFormat) ? (draft.templateHeaderUrl || "") : ""),
                        });
                      }}
                      disabled={templatesLoading}
                    >
                      <option value="">{templatesLoading ? "Loading…" : "Select template…"}</option>
                      {approvedTemplates.map((t) => (
                        <option key={`${t.name}:${t.language}`} value={t.name}>{t.name} ({t.language})</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Language</div>
                    <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={draft.templateLanguage || "en"} onChange={(e) => onChange({ templateLanguage: e.target.value })} />
                  </div>
                </div>

                {(() => {
                  try {
                    const tn = String(draft.templateName || "").trim();
                    if (!tn) return null;
                    const tpl = approvedTemplates.find((t) => t.name === tn) || null;
                    const comps = Array.isArray(tpl?.components) ? tpl.components : [];
                    const h = comps.find((c) => String(c?.type || "").toUpperCase() === "HEADER") || null;
                    const fmt = String(h?.format || "").toUpperCase();
                    if (!["IMAGE", "VIDEO", "DOCUMENT"].includes(fmt)) return null;
                    return (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <div className="md:col-span-2">
                          <div className="text-xs text-slate-500 mb-1">Header {fmt} URL</div>
                          <input
                            className="w-full border rounded px-2 py-1 font-mono text-xs"
                            value={draft.templateHeaderUrl || ""}
                            onChange={(e) => onChange({ templateHeaderUrl: e.target.value })}
                            placeholder="https://... (public image/video/pdf URL)"
                          />
                          <div className="text-[11px] text-slate-500 mt-1">
                            This template requires a {fmt} header. If you leave it empty, WhatsApp will reject the message (error 132012).
                          </div>
                        </div>
                      </div>
                    );
                  } catch {
                    return null;
                  }
                })()}

                {(Array.isArray(draft.templateVars) && draft.templateVars.length > 0) && (
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Body variables</div>
                    {draft.triggerSource === "shopify" && (
                      <div className="mb-2">
                        <div className="text-[11px] text-slate-500 mb-1">Insert Shopify variable (click to copy then paste into Var fields)</div>
                        <div className="flex flex-wrap gap-1">
                          {shopifyVarsByTopic(draft.shopifyTopic).slice(0, 24).map((v) => (
                            <button
                              key={`shopvar2:${v}`}
                              type="button"
                              className="px-2 py-0.5 rounded border text-xs hover:bg-slate-50"
                              onClick={() => copyVar(v)}
                            >
                              {v}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                    {draft.triggerSource === "delivery" && (
                      <div className="mb-2">
                        <div className="text-[11px] text-slate-500 mb-1">Insert Delivery variable (click to copy then paste into Var fields)</div>
                        <div className="flex flex-wrap gap-1">
                          {DELIVERY_VARS.slice(0, 24).map((v) => (
                            <button
                              key={`delvar2:${v}`}
                              type="button"
                              className="px-2 py-0.5 rounded border text-xs hover:bg-slate-50"
                              onClick={() => copyVar(v)}
                            >
                              {v}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {draft.templateVars.map((v, idx) => (
                        <input
                          key={`tplvar:${idx}`}
                          className="w-full border rounded px-2 py-1"
                          placeholder={`Var ${idx + 1} (e.g. {{ order_number }})`}
                          value={v}
                          onChange={(e) => {
                            const next = [...draft.templateVars];
                            next[idx] = e.target.value;
                            onChange({ templateVars: next });
                          }}
                        />
                      ))}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      Variables support dotted paths like <span className="font-mono">{"{{ customer.phone }}"}</span>.
                    </div>
                  </div>
                )}

                {draft.actionMode === "order_confirm" && (
                  <div className="mt-2 space-y-3">
                    <div className="text-xs font-semibold text-slate-700">Button click branches</div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-500 mb-1">Button 1 titles (one per line)</div>
                        <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={2} value={draft.ocConfirmTitles || ""} onChange={(e)=>onChange({ ocConfirmTitles: e.target.value })} />
                      </div>
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-500 mb-1">Button 2 titles (one per line)</div>
                        <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={2} value={draft.ocChangeTitles || ""} onChange={(e)=>onChange({ ocChangeTitles: e.target.value })} />
                      </div>
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-500 mb-1">Button 3 titles (one per line)</div>
                        <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={2} value={draft.ocTalkTitles || ""} onChange={(e)=>onChange({ ocTalkTitles: e.target.value })} />
                      </div>

                      <div className="md:col-span-2 text-[11px] text-slate-500">
                        Prefer matching by button <span className="font-mono">id</span> if your template buttons have stable IDs.
                      </div>

                      <div>
                        <div className="text-xs text-slate-500 mb-1">Button 1 IDs (optional)</div>
                        <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={2} value={draft.ocConfirmIds || ""} onChange={(e)=>onChange({ ocConfirmIds: e.target.value })} />
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Button 2 IDs (optional)</div>
                        <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={2} value={draft.ocChangeIds || ""} onChange={(e)=>onChange({ ocChangeIds: e.target.value })} />
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Button 3 IDs (optional)</div>
                        <textarea className="w-full border rounded px-2 py-1 font-mono text-xs" rows={2} value={draft.ocTalkIds || ""} onChange={(e)=>onChange({ ocTalkIds: e.target.value })} />
                      </div>

                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-500 mb-1">Button 1 audio URL (optional)</div>
                        <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={draft.ocConfirmAudioUrl || ""} onChange={(e)=>onChange({ ocConfirmAudioUrl: e.target.value })} placeholder="https://.../confirm.ogg" />
                      </div>
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-500 mb-1">Button 2 audio URL (optional)</div>
                        <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={draft.ocChangeAudioUrl || ""} onChange={(e)=>onChange({ ocChangeAudioUrl: e.target.value })} placeholder="https://.../change.ogg" />
                      </div>
                      <div className="md:col-span-2">
                        <div className="text-xs text-slate-500 mb-1">Button 3 audio URL (optional)</div>
                        <input className="w-full border rounded px-2 py-1 font-mono text-xs" value={draft.ocTalkAudioUrl || ""} onChange={(e)=>onChange({ ocTalkAudioUrl: e.target.value })} placeholder="https://.../talk.ogg" />
                      </div>

                      <div className="md:col-span-2 flex items-center justify-between gap-3">
                        <label className="text-sm flex items-center gap-2">
                          <input type="checkbox" checked={!!draft.ocSendItems} onChange={(e)=>onChange({ ocSendItems: e.target.checked })} />
                          Send ordered items after Button 1 (catalog items)
                        </label>
                        <div className="flex items-center gap-2">
                          <div className="text-xs text-slate-500">Max items</div>
                          <input type="number" className="w-24 border rounded px-2 py-1" value={draft.ocMaxItems || 10} onChange={(e)=>onChange({ ocMaxItems: Number(e.target.value || 10) })} />
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <>
                <div className="text-xs text-slate-500 mb-1">Auto-reply text</div>
                <textarea className="w-full border rounded px-2 py-1" rows={5} value={draft.replyText} onChange={(e) => onChange({ replyText: e.target.value })} placeholder="Type the WhatsApp message to send…" />
                <div className="text-[11px] text-slate-500 mt-1">
                  Variables: <span className="font-mono">{"{{ phone }}"}</span>, <span className="font-mono">{"{{ text }}"}</span>, <span className="font-mono">{"{{ order_number }}"}</span>, <span className="font-mono">{"{{ total_price }}"}</span>, <span className="font-mono">{"{{ customer.phone }}"}</span>
                </div>
              </>
            )}
          </div>
          <div className="md:col-span-2">
            <div className="text-xs text-slate-500 mb-1">Optional tag to add</div>
            <input className="w-full border rounded px-2 py-1" value={draft.tag} onChange={(e) => onChange({ tag: e.target.value })} placeholder="e.g. Auto" />
          </div>
          <div className="md:col-span-2">
            <label className="text-sm flex items-center gap-2">
              <input type="checkbox" checked={!!draft.enabled} onChange={(e) => onChange({ enabled: e.target.checked })} />
              Enabled
            </label>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-end gap-2">
          <button className="px-3 py-1.5 border rounded text-sm" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white" onClick={onSave} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
*/

// (Unused) Environment editor kept for backward compatibility; the UI entry point was removed.
function InboxEnvSettings({ loading, saving, error, values, onChange, onRefresh, onSave }) {
  return (
    <div className="p-4 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-lg font-semibold">Environment</div>
          <div className="text-sm text-slate-500">
            Configure inbox/automation settings without Cloud Run env vars (admin only). Changes apply per workspace.
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 border rounded text-sm" onClick={onRefresh} disabled={loading || saving}>Refresh</button>
          <button className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white" onClick={onSave} disabled={loading || saving}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>

      {error && <div className="mb-3 p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{error}</div>}
      {loading ? (
        <div className="text-sm text-slate-500">Loading…</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="md:col-span-2">
            <div className="text-xs text-slate-500 mb-1">WhatsApp Business Account ID (WABA ID)</div>
            <input
              className="w-full border rounded px-2 py-1 font-mono text-xs"
              value={values.waba_id || ""}
              onChange={(e) => onChange({ waba_id: e.target.value })}
              placeholder="e.g. 123456789012345"
            />
            <div className="text-[11px] text-slate-500 mt-1">
              Used to list WhatsApp message templates (Admin API). Not secret.
            </div>
          </div>

          <div className="md:col-span-2">
            <div className="text-xs text-slate-500 mb-1">ALLOWED_PHONE_NUMBER_IDS (one per line)</div>
            <textarea
              className="w-full border rounded px-2 py-1 font-mono text-xs"
              rows={5}
              value={values.allowed_phone_number_ids || ""}
              onChange={(e) => onChange({ allowed_phone_number_ids: e.target.value })}
              placeholder="e.g.\n123456789012345\n987654321098765"
            />
            <div className="text-[11px] text-slate-500 mt-1">
              If set, webhooks for other phone_number_id values will be ignored.
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-500 mb-1">SURVEY_TEST_NUMBERS (digits only; one per line)</div>
            <textarea
              className="w-full border rounded px-2 py-1 font-mono text-xs"
              rows={6}
              value={values.survey_test_numbers || ""}
              onChange={(e) => onChange({ survey_test_numbers: e.target.value })}
              placeholder="e.g.\n212600000000"
            />
          </div>

          <div>
            <div className="text-xs text-slate-500 mb-1">AUTO_REPLY_TEST_NUMBERS (digits only; one per line)</div>
            <textarea
              className="w-full border rounded px-2 py-1 font-mono text-xs"
              rows={6}
              value={values.auto_reply_test_numbers || ""}
              onChange={(e) => onChange({ auto_reply_test_numbers: e.target.value })}
              placeholder="e.g.\n212611111111"
            />
          </div>
        </div>
      )}
    </div>
  );
}


