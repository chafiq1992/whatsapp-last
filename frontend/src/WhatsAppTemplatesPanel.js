import React, { useMemo, useState } from "react";
import api from "./api";

const CATEGORY_OPTIONS = [
  { id: "MARKETING", label: "Marketing", desc: "Promotions, offers, product announcements." },
  { id: "UTILITY", label: "Utility", desc: "Order updates, account alerts, reminders." },
  { id: "AUTHENTICATION", label: "Authentication", desc: "One-time passwords and verification." },
];

const TYPE_OPTIONS = [
  { id: "DEFAULT", label: "Default", desc: "Send messages about an existing order or account." },
  { id: "FLOWS", label: "Flows", desc: "Send a form to collect feedback, send reminders or manage orders." },
  { id: "CALL_PERMISSION", label: "Calling permissions request", desc: "Ask customers if you can call them on WhatsApp." },
];

const LANGUAGE_OPTIONS = [
  { code: "en", label: "English" },
  { code: "fr", label: "French" },
  { code: "ar", label: "Arabic" },
  { code: "es", label: "Spanish" },
  { code: "it", label: "Italian" },
  { code: "de", label: "German" },
  { code: "pt_BR", label: "Portuguese (Brazil)" },
  { code: "en_US", label: "English (US)" },
  { code: "en_GB", label: "English (UK)" },
];

function normalizeTemplateName(input) {
  // Meta template names: lowercase, numbers, underscores (best-effort).
  try {
    return String(input || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "_")
      .replace(/[^a-z0-9_]+/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 512);
  } catch {
    return "";
  }
}

function statusPill(status) {
  const s = String(status || "").toUpperCase();
  const base = "text-xs px-2 py-0.5 rounded border inline-flex items-center";
  if (s === "APPROVED") return `${base} bg-emerald-50 text-emerald-700 border-emerald-200`;
  if (s === "PENDING" || s === "PENDING_REVIEW") return `${base} bg-amber-50 text-amber-700 border-amber-200`;
  if (s === "REJECTED") return `${base} bg-rose-50 text-rose-700 border-rose-200`;
  return `${base} bg-slate-50 text-slate-700 border-slate-200`;
}

function categoryPill(category) {
  const c = String(category || "").toUpperCase();
  const base = "text-xs px-2 py-0.5 rounded border inline-flex items-center";
  if (c === "UTILITY") return `${base} bg-indigo-50 text-indigo-700 border-indigo-200`;
  if (c === "MARKETING") return `${base} bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200`;
  if (c === "AUTHENTICATION") return `${base} bg-sky-50 text-sky-700 border-sky-200`;
  return `${base} bg-slate-50 text-slate-700 border-slate-200`;
}

export default function WhatsAppTemplatesPanel({ templates, loading, error, onRefresh }) {
  const [createOpen, setCreateOpen] = useState(false);

  const sorted = useMemo(() => {
    const arr = Array.isArray(templates) ? [...templates] : [];
    arr.sort((a, b) => String(a?.name || "").localeCompare(String(b?.name || "")));
    return arr;
  }, [templates]);

  return (
    <div className="p-4 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-lg font-semibold">WhatsApp Templates</div>
          <div className="text-sm text-slate-500">
            View current templates and create new ones to submit to Meta for review.
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 border rounded text-sm" onClick={onRefresh} disabled={loading}>
            Refresh
          </button>
          <button
            className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white disabled:opacity-50"
            onClick={() => setCreateOpen(true)}
            disabled={loading}
          >
            + Add template
          </button>
        </div>
      </div>

      {error && <div className="mb-3 p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{error}</div>}
      {loading && <div className="text-sm text-slate-500">Loading…</div>}

      {!loading && (
        <div className="border rounded bg-white overflow-hidden">
          <div className="px-3 py-2 border-b text-sm font-medium">Templates</div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="text-left font-medium px-3 py-2">Name</th>
                  <th className="text-left font-medium px-3 py-2">Status</th>
                  <th className="text-left font-medium px-3 py-2">Category</th>
                  <th className="text-left font-medium px-3 py-2">Language</th>
                  <th className="text-left font-medium px-3 py-2">Components</th>
                </tr>
              </thead>
              <tbody>
                {sorted.length === 0 ? (
                  <tr>
                    <td className="px-3 py-3 text-slate-500" colSpan={5}>
                      No templates found for this workspace. Add your first template.
                    </td>
                  </tr>
                ) : (
                  sorted.map((t) => (
                    <tr key={`${t?.name || ""}:${t?.language || ""}`} className="border-t">
                      <td className="px-3 py-2">
                        <div className="font-semibold">{String(t?.name || "")}</div>
                      </td>
                      <td className="px-3 py-2">
                        <span className={statusPill(t?.status)}>{String(t?.status || "").toUpperCase() || "—"}</span>
                      </td>
                      <td className="px-3 py-2">
                        <span className={categoryPill(t?.category)}>{String(t?.category || "").toUpperCase() || "—"}</span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">{String(t?.language || "") || "—"}</td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {Array.isArray(t?.components) ? t.components.map((c) => String(c?.type || "")).filter(Boolean).join(", ") : "—"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {createOpen && (
        <CreateTemplateModal
          onClose={() => setCreateOpen(false)}
          onCreated={async () => {
            try { await onRefresh(); } catch {}
          }}
        />
      )}
    </div>
  );
}

function CreateTemplateModal({ onClose, onCreated }) {
  const [step, setStep] = useState(1); // 1 category, 2 type, 3 editor
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState("");

  const [category, setCategory] = useState("UTILITY");
  const [templateType, setTemplateType] = useState("DEFAULT");

  const [name, setName] = useState("");
  const [language, setLanguage] = useState("en");

  const [headerType, setHeaderType] = useState("NONE"); // NONE | TEXT
  const [headerText, setHeaderText] = useState("");
  const [bodyText, setBodyText] = useState("Hello");
  const [footerText, setFooterText] = useState("");

  const [buttons, setButtons] = useState([]); // { type: QUICK_REPLY|URL, text, url? }

  const normName = useMemo(() => normalizeTemplateName(name), [name]);

  const langLabel = useMemo(() => {
    const hit = LANGUAGE_OPTIONS.find((l) => l.code === language);
    return hit ? hit.label : language;
  }, [language]);

  const canContinueType = true;
  const typeNotSupported = templateType !== "DEFAULT";

  const validation = useMemo(() => {
    const e = [];
    if (!normName) e.push("You need to enter a name for your template.");
    if (!language) e.push("Select a language.");
    if (headerType === "TEXT" && !String(headerText || "").trim()) e.push("Header text is required when Header type is Text.");
    if (!String(bodyText || "").trim()) e.push("Body is required.");
    if (buttons.length > 10) e.push("You can add up to ten buttons.");
    for (const b of buttons) {
      const t = String(b?.type || "");
      const txt = String(b?.text || "").trim();
      if (!txt) e.push("Each button needs text.");
      if (t === "URL" && !String(b?.url || "").trim()) e.push("URL buttons require a URL.");
    }
    if (typeNotSupported) e.push("Flows and Calling permission request templates are not supported yet in this UI.");
    return e;
  }, [normName, language, headerType, headerText, bodyText, buttons, typeNotSupported]);

  const buildComponents = () => {
    const comps = [];
    if (headerType === "TEXT" && String(headerText || "").trim()) {
      comps.push({ type: "HEADER", format: "TEXT", text: String(headerText || "").trim() });
    }
    comps.push({ type: "BODY", text: String(bodyText || "") });
    if (String(footerText || "").trim()) comps.push({ type: "FOOTER", text: String(footerText || "").trim() });
    if (buttons.length) {
      comps.push({
        type: "BUTTONS",
        buttons: buttons.map((b) => {
          const t = String(b?.type || "QUICK_REPLY").toUpperCase();
          if (t === "URL") {
            return { type: "URL", text: String(b?.text || "").trim(), url: String(b?.url || "").trim() };
          }
          return { type: "QUICK_REPLY", text: String(b?.text || "").trim() };
        }),
      });
    }
    return comps;
  };

  const submit = async () => {
    setErr("");
    if (validation.length) {
      setErr(validation[0]);
      return;
    }
    setSubmitting(true);
    try {
      const payload = {
        name: normName,
        language,
        category,
        template_type: templateType,
        components: buildComponents(),
      };
      await api.post("/admin/whatsapp/templates", payload);
      try { await onCreated(); } catch {}
      onClose();
    } catch (e) {
      const msg =
        e?.response?.data?.detail ||
        e?.response?.data?.error?.message ||
        (typeof e?.message === "string" ? e.message : "") ||
        "Failed to submit template.";
      setErr(String(msg).slice(0, 500));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-[200]" onClick={onClose}>
      <div className="w-[980px] max-w-[94vw] bg-white rounded-xl border shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="px-4 py-3 border-b flex items-center justify-between">
          <div className="font-semibold">Create WhatsApp template</div>
          <button className="px-2 py-1 border rounded text-sm" onClick={onClose}>✕</button>
        </div>

        <div className="p-4">
          {err && <div className="mb-3 p-2 rounded border border-rose-200 bg-rose-50 text-rose-700 text-sm">{err}</div>}

          {step === 1 && (
            <div>
              <div className="text-sm font-semibold mb-2">Choose template category</div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {CATEGORY_OPTIONS.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    className={`p-3 rounded border text-left ${category === c.id ? "border-blue-300 bg-blue-50" : "border-slate-200 hover:bg-slate-50"}`}
                    onClick={() => setCategory(c.id)}
                  >
                    <div className="font-semibold">{c.label}</div>
                    <div className="text-xs text-slate-500 mt-1">{c.desc}</div>
                  </button>
                ))}
              </div>
              <div className="mt-4 flex justify-end gap-2">
                <button className="px-3 py-1.5 border rounded text-sm" onClick={onClose}>Cancel</button>
                <button className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white" onClick={() => setStep(2)}>
                  Continue
                </button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div>
              <div className="text-sm font-semibold mb-1">Set up your template</div>
              <div className="text-xs text-slate-500 mb-3">
                Choose the category that best describes your message template. Then, select the type of message that you want to send.
              </div>

              <div className="border rounded p-3 bg-slate-50">
                <div className="text-xs text-slate-500 mb-2">Selected category</div>
                <div className="flex items-center gap-2">
                  <span className={categoryPill(category)}>{category}</span>
                  <span className="text-sm text-slate-700">
                    {CATEGORY_OPTIONS.find((x) => x.id === category)?.label || category}
                  </span>
                </div>
              </div>

              <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
                {TYPE_OPTIONS.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    className={`p-3 rounded border text-left ${templateType === t.id ? "border-blue-300 bg-blue-50" : "border-slate-200 hover:bg-slate-50"}`}
                    onClick={() => setTemplateType(t.id)}
                  >
                    <div className="font-semibold">{t.label}</div>
                    <div className="text-xs text-slate-500 mt-1">{t.desc}</div>
                  </button>
                ))}
              </div>

              {templateType !== "DEFAULT" && (
                <div className="mt-3 p-2 rounded border border-amber-200 bg-amber-50 text-amber-800 text-sm">
                  This app currently supports creating <b>Default</b> templates only. (Flows / Calling permissions request coming next.)
                </div>
              )}

              <div className="mt-4 flex justify-between gap-2">
                <button className="px-3 py-1.5 border rounded text-sm" onClick={() => setStep(1)}>Back</button>
                <button
                  className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white disabled:opacity-50"
                  onClick={() => setStep(3)}
                  disabled={!canContinueType}
                >
                  Continue
                </button>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <div className="lg:col-span-8">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className="text-sm font-semibold">Set up template</div>
                    <div className="text-xs text-slate-500">
                      <span className="font-mono">{normName || "your_template_name"}</span> • {langLabel}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={categoryPill(category)}>{category}</span>
                    <span className="text-xs px-2 py-0.5 rounded border bg-slate-50 text-slate-700 border-slate-200">{templateType}</span>
                  </div>
                </div>

                <div className="border rounded bg-white">
                  <div className="px-3 py-2 border-b text-sm font-medium">Template name and language</div>
                  <div className="p-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Message template name</div>
                      <input
                        className="w-full border rounded px-2 py-1"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="Enter a template name"
                      />
                      <div className="text-[11px] text-slate-500 mt-1">
                        Normalized: <span className="font-mono">{normName || "—"}</span> • {String(normName || "").length}/512
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Select language</div>
                      <select className="w-full border rounded px-2 py-1" value={language} onChange={(e) => setLanguage(e.target.value)}>
                        {LANGUAGE_OPTIONS.map((l) => (
                          <option key={l.code} value={l.code}>{l.label}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>

                <div className="border rounded bg-white mt-3">
                  <div className="px-3 py-2 border-b text-sm font-medium">Content</div>
                  <div className="p-3 space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Header type</div>
                        <select className="w-full border rounded px-2 py-1" value={headerType} onChange={(e) => setHeaderType(e.target.value)}>
                          <option value="NONE">None</option>
                          <option value="TEXT">Text</option>
                        </select>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Header (optional)</div>
                        <input
                          className="w-full border rounded px-2 py-1"
                          value={headerText}
                          onChange={(e) => setHeaderText(e.target.value.slice(0, 60))}
                          placeholder="Add a short line of text to the header"
                          disabled={headerType !== "TEXT"}
                        />
                        <div className="text-[11px] text-slate-500 mt-1">{String(headerText || "").length}/60</div>
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500 mb-1">Body</div>
                      <textarea
                        className="w-full border rounded px-2 py-1"
                        rows={6}
                        value={bodyText}
                        onChange={(e) => setBodyText(e.target.value.slice(0, 1024))}
                        placeholder="Enter text"
                      />
                      <div className="text-[11px] text-slate-500 mt-1">{String(bodyText || "").length}/1024</div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500 mb-1">Footer (optional)</div>
                      <input
                        className="w-full border rounded px-2 py-1"
                        value={footerText}
                        onChange={(e) => setFooterText(e.target.value.slice(0, 60))}
                        placeholder="Enter text"
                      />
                      <div className="text-[11px] text-slate-500 mt-1">{String(footerText || "").length}/60</div>
                    </div>
                  </div>
                </div>

                <div className="border rounded bg-white mt-3">
                  <div className="px-3 py-2 border-b text-sm font-medium flex items-center justify-between">
                    <span>Buttons (optional)</span>
                    <button
                      type="button"
                      className="px-2 py-1 border rounded text-sm disabled:opacity-50"
                      onClick={() => setButtons((prev) => (prev.length >= 10 ? prev : [...prev, { type: "QUICK_REPLY", text: "" }]))}
                      disabled={buttons.length >= 10}
                    >
                      + Add button
                    </button>
                  </div>
                  <div className="p-3 space-y-2">
                    {buttons.length === 0 ? (
                      <div className="text-sm text-slate-500">No buttons.</div>
                    ) : (
                      buttons.map((b, idx) => (
                        <div key={`btn:${idx}`} className="border rounded p-2">
                          <div className="flex items-center justify-between">
                            <div className="text-xs font-semibold text-slate-700">Button {idx + 1}</div>
                            <button
                              type="button"
                              className="px-2 py-1 border rounded text-xs text-rose-700 border-rose-200"
                              onClick={() => setButtons((prev) => prev.filter((_, i) => i !== idx))}
                            >
                              Remove
                            </button>
                          </div>
                          <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-2">
                            <div>
                              <div className="text-xs text-slate-500 mb-1">Type</div>
                              <select
                                className="w-full border rounded px-2 py-1"
                                value={String(b?.type || "QUICK_REPLY")}
                                onChange={(e) => {
                                  const v = e.target.value;
                                  setButtons((prev) => prev.map((x, i) => (i === idx ? { ...x, type: v } : x)));
                                }}
                              >
                                <option value="QUICK_REPLY">Quick reply</option>
                                <option value="URL">Visit website</option>
                              </select>
                            </div>
                            <div className="md:col-span-2">
                              <div className="text-xs text-slate-500 mb-1">Text</div>
                              <input
                                className="w-full border rounded px-2 py-1"
                                value={String(b?.text || "")}
                                onChange={(e) => setButtons((prev) => prev.map((x, i) => (i === idx ? { ...x, text: e.target.value.slice(0, 25) } : x)))}
                                placeholder="Button text"
                              />
                            </div>
                            {String(b?.type || "") === "URL" && (
                              <div className="md:col-span-3">
                                <div className="text-xs text-slate-500 mb-1">URL</div>
                                <input
                                  className="w-full border rounded px-2 py-1 font-mono text-xs"
                                  value={String(b?.url || "")}
                                  onChange={(e) => setButtons((prev) => prev.map((x, i) => (i === idx ? { ...x, url: e.target.value } : x)))}
                                  placeholder="https://example.com"
                                />
                              </div>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                    {buttons.length > 3 && (
                      <div className="text-[11px] text-slate-500">
                        If you add more than three buttons, WhatsApp may display them in a list.
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-between gap-2">
                  <button className="px-3 py-1.5 border rounded text-sm" onClick={() => setStep(2)} disabled={submitting}>Back</button>
                  <div className="flex items-center gap-2">
                    <button className="px-3 py-1.5 border rounded text-sm" onClick={onClose} disabled={submitting}>Cancel</button>
                    <button
                      className="px-3 py-1.5 rounded text-sm bg-blue-600 text-white disabled:opacity-50"
                      onClick={submit}
                      disabled={submitting || validation.length > 0}
                      title={validation.length ? validation[0] : "Submit for Review"}
                    >
                      {submitting ? "Submitting…" : "Submit for Review"}
                    </button>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-4">
                <div className="border rounded bg-white sticky top-16">
                  <div className="px-3 py-2 border-b text-sm font-medium">Template preview</div>
                  <div className="p-3">
                    <div className="border rounded-xl p-3 bg-slate-50">
                      {headerType === "TEXT" && String(headerText || "").trim() && (
                        <div className="text-xs font-semibold text-slate-700 mb-2">{String(headerText || "").trim()}</div>
                      )}
                      <div className="text-sm whitespace-pre-wrap">{String(bodyText || "")}</div>
                      {String(footerText || "").trim() && (
                        <div className="text-xs text-slate-500 mt-2">{String(footerText || "").trim()}</div>
                      )}
                      {buttons.length > 0 && (
                        <div className="mt-3 space-y-2">
                          {buttons.slice(0, 10).map((b, i) => (
                            <div key={`pbtn:${i}`} className="text-center text-sm px-2 py-2 rounded border bg-white">
                              {String(b?.text || "").trim() || "Button"}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-2">
                      Preview is approximate. Final rendering depends on WhatsApp client.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


