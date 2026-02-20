import React, { useEffect, useMemo, useState } from "react";
import api from "./api";

function formatInt(n) {
  try {
    return new Intl.NumberFormat().format(Number(n || 0));
  } catch {
    return String(n || 0);
  }
}

function formatPct(x) {
  try {
    return `${Number(x || 0).toFixed(2)}%`;
  } catch {
    return "0%";
  }
}

function defaultDsl() {
  return [
    "FROM customers",
    "",
    "SHOW customer_name, note, email_subscription_status, location, orders, amount_spent",
    "",
    "WHERE number_of_orders > 2",
    "",
    "AND last_order_date < -90d",
    "",
    "ORDER BY updated_at",
  ].join("\n");
}

export default function CustomersSegmentsPage({ embedded = false }) {
  const [stores, setStores] = useState([]);
  const [storeId, setStoreId] = useState(() => {
    try {
      return localStorage.getItem("customers_segment_store") || "";
    } catch {
      return "";
    }
  });

  const [dsl, setDsl] = useState(() => {
    try {
      return localStorage.getItem("customers_segment_dsl") || defaultDsl();
    } catch {
      return defaultDsl();
    }
  });
  const [pageInfo, setPageInfo] = useState(null);

  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const [customers, setCustomers] = useState([]);
  const [compiledQuery, setCompiledQuery] = useState("");
  const [conditions, setConditions] = useState([]);
  const [description, setDescription] = useState("");
  const [segmentCount, setSegmentCount] = useState(null);
  const [baseCount, setBaseCount] = useState(null);
  const [segmentCountIsEstimate, setSegmentCountIsEstimate] = useState(false);
  const [nextPageInfo, setNextPageInfo] = useState(null);
  const [prevPageInfo, setPrevPageInfo] = useState(null);

  const percentOfBase = useMemo(() => {
    if (typeof segmentCount !== "number" || typeof baseCount !== "number" || baseCount <= 0) return null;
    return (segmentCount / baseCount) * 100;
  }, [segmentCount, baseCount]);

  const [segments, setSegments] = useState([]);
  const [segmentSearch, setSegmentSearch] = useState("");
  const [activeSegmentId, setActiveSegmentId] = useState("");
  const [activeSegmentName, setActiveSegmentName] = useState("");
  const loadSegments = async () => {
    try {
      const res = await api.get("/customer-segments");
      setSegments(Array.isArray(res?.data) ? res.data : []);
    } catch {
      setSegments([]);
    }
  };

  const [importing, setImporting] = useState(false);
  const importShopifySegments = async () => {
    try {
      setImporting(true);
      await api.post("/customer-segments/import-shopify", { store: storeId || null, limit: 500 });
      await loadSegments();
      alert("Imported Shopify segments");
    } catch (e) {
      alert(e?.response?.data?.detail || "Failed to import Shopify segments");
    } finally {
      setImporting(false);
    }
  };

  const filteredSegments = useMemo(() => {
    const q = String(segmentSearch || "").trim().toLowerCase();
    const arr = Array.isArray(segments) ? segments : [];
    if (!q) return arr;
    return arr.filter((s) => {
      const name = String(s?.name || "").toLowerCase();
      const desc = String(s?.description || "").toLowerCase();
      const st = String(s?.store || "").toLowerCase();
      return name.includes(q) || desc.includes(q) || st.includes(q);
    });
  }, [segments, segmentSearch]);

  useEffect(() => {
    loadSegments();
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const res = await api.get("/shopify-stores");
        const arr = Array.isArray(res?.data) ? res.data : [];
        if (!alive) return;
        setStores(arr);
        if (!storeId && arr.length) {
          setStoreId(String(arr[0].id || ""));
        }
      } catch {
        if (!alive) return;
        setStores([]);
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    try {
      if (storeId) localStorage.setItem("customers_segment_store", storeId);
    } catch {}
  }, [storeId]);

  useEffect(() => {
    try {
      localStorage.setItem("customers_segment_dsl", dsl || "");
    } catch {}
  }, [dsl]);

  useEffect(() => {
    // reset pagination on DSL/store change
    setPageInfo(null);
  }, [dsl, storeId]);

  const preview = async () => {
    setErr("");
    setLoading(true);
    try {
      const res = await api.get("/shopify-segment-preview", {
        params: {
          dsl,
          ...(storeId ? { store: storeId } : {}),
          ...(pageInfo ? { page_info: pageInfo } : {}),
        },
      });
      const data = res?.data || {};
      setCustomers(Array.isArray(data.customers) ? data.customers : []);
      setCompiledQuery(String(data.compiled_query || ""));
      setConditions(Array.isArray(data.conditions) ? data.conditions : []);
      setDescription(String(data.description || ""));
      setSegmentCount(typeof data.segment_count === "number" ? data.segment_count : null);
      setBaseCount(typeof data.base_count === "number" ? data.base_count : null);
      setSegmentCountIsEstimate(Boolean(data.segment_count_is_estimate));
      setNextPageInfo(data.next_page_info || null);
      setPrevPageInfo(data.prev_page_info || null);
    } catch (e) {
      const msg = e?.response?.data?.detail || e?.message || "Failed to preview segment";
      setErr(String(msg));
      setCustomers([]);
      setCompiledQuery("");
      setConditions([]);
      setDescription("");
      setSegmentCount(null);
      setBaseCount(null);
      setSegmentCountIsEstimate(false);
      setNextPageInfo(null);
      setPrevPageInfo(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    preview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageInfo]);

  const handleSaveSegment = async ({ asNew = false } = {}) => {
    try {
      const defaultName = activeSegmentName || "My segment";
      const name = window.prompt("Segment name?", defaultName);
      if (!name) return;
      const payload = {
        name,
        dsl,
        store: storeId || null,
        ...(activeSegmentId && !asNew ? { id: activeSegmentId } : {}),
      };
      const res = await api.post("/customer-segments", payload);
      await loadSegments();
      const saved = res?.data || null;
      if (saved?.id && !asNew) {
        setActiveSegmentId(String(saved.id));
        setActiveSegmentName(String(saved.name || ""));
      }
      if (saved?.id && asNew) {
        setActiveSegmentId(String(saved.id));
        setActiveSegmentName(String(saved.name || ""));
      }
      alert(activeSegmentId && !asNew ? "Saved changes" : "Saved segment");
    } catch (e) {
      alert("Failed to save segment");
    }
  };

  const handleDeleteSegment = async () => {
    const sid = String(activeSegmentId || "").trim();
    if (!sid) return;
    const ok = window.confirm("Delete this saved segment?");
    if (!ok) return;
    try {
      await api.delete(`/customer-segments/${encodeURIComponent(sid)}`);
      await loadSegments();
      setActiveSegmentId("");
      setActiveSegmentName("");
      alert("Deleted segment");
    } catch {
      alert("Failed to delete segment");
    }
  };

  const [campaignJobId, setCampaignJobId] = useState("");
  const [campaignJob, setCampaignJob] = useState(null);
  const [launching, setLaunching] = useState(false);

  const pollJob = async (id) => {
    try {
      const res = await api.get(`/customer-campaigns/${encodeURIComponent(id)}`);
      setCampaignJob(res?.data || null);
    } catch {}
  };

  useEffect(() => {
    if (!campaignJobId) return;
    pollJob(campaignJobId);
    const t = setInterval(() => pollJob(campaignJobId), 1500);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [campaignJobId]);

  const launchCampaign = async () => {
    if (!compiledQuery) {
      alert("Preview a valid segment first.");
      return;
    }
    try {
      setLaunching(true);
      // Pick template from admin templates
      let templates = [];
      try {
        const tr = await api.get("/admin/whatsapp/templates");
        templates = Array.isArray(tr?.data) ? tr.data : [];
      } catch {}
      const first = templates && templates.length ? templates[0] : null;
      const tplName = window.prompt("Template name?", String(first?.name || ""));
      if (!tplName) return;
      const lang = window.prompt("Language? (e.g. en, fr, ar)", String(first?.language || "en")) || "en";
      const limStr = window.prompt("How many customers to send? (50 default, 0 = all)", "50") || "50";
      const limit = Number(limStr);
      const res = await api.post("/customer-campaigns/launch", {
        dsl,
        store: storeId || null,
        template_name: tplName,
        language: lang,
        limit: Number.isFinite(limit) ? limit : 50,
      });
      const jid = String(res?.data?.job_id || "");
      if (jid) {
        setCampaignJobId(jid);
        alert(`Campaign started. Job: ${jid}`);
      }
    } catch (e) {
      alert(e?.response?.data?.detail || "Failed to launch campaign");
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className={embedded ? "h-full w-full bg-transparent overflow-auto" : "min-h-screen w-screen bg-white"}>
      {!embedded && (
        <div className="h-12 border-b flex items-center justify-between px-3">
          <div className="flex items-center gap-2">
            <div className="font-medium">Customers</div>
          </div>
          <div className="flex items-center gap-2">
            {stores.length > 0 && (
              <select className="border rounded px-2 py-1 text-sm bg-white" value={storeId} onChange={(e) => setStoreId(e.target.value)}>
                {stores.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id}
                  </option>
                ))}
              </select>
            )}
            <button className="px-3 py-1.5 text-sm border rounded" onClick={preview} disabled={loading}>
              {loading ? "Loading…" : "Preview"}
            </button>
            <button className="px-3 py-1.5 text-sm border rounded disabled:opacity-60" onClick={importShopifySegments} disabled={importing}>
              {importing ? "Importing…" : "Import Shopify segments"}
            </button>
            <div className="flex items-center gap-2">
              <button className="px-3 py-1.5 text-sm bg-slate-900 text-white rounded" onClick={() => handleSaveSegment({ asNew: false })}>
                {activeSegmentId ? "Save changes" : "Save segment"}
              </button>
              {activeSegmentId && (
                <button className="px-3 py-1.5 text-sm border rounded" onClick={() => handleSaveSegment({ asNew: true })}>
                  Save as new
                </button>
              )}
            </div>
            <button className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded disabled:opacity-60" onClick={launchCampaign} disabled={launching}>
              {launching ? "Launching…" : "Launch campaign"}
            </button>
          </div>
        </div>
      )}

      <div className={embedded ? "max-w-6xl mx-auto px-6 py-6" : "max-w-6xl mx-auto px-6 py-6"}>
        {embedded && (
          <div className="flex items-center justify-between gap-3 mb-4">
            <div className="text-xl font-semibold text-slate-900">Customers</div>
            <div className="flex items-center gap-2">
              {stores.length > 0 && (
                <select className="border rounded px-2 py-1 text-sm bg-white" value={storeId} onChange={(e) => setStoreId(e.target.value)}>
                  {stores.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id}
                    </option>
                  ))}
                </select>
              )}
              <button className="px-3 py-1.5 text-sm border rounded" onClick={preview} disabled={loading}>
                {loading ? "Loading…" : "Preview"}
              </button>
              <button className="px-3 py-1.5 text-sm border rounded disabled:opacity-60" onClick={importShopifySegments} disabled={importing}>
                {importing ? "Importing…" : "Import Shopify segments"}
              </button>
              <div className="flex items-center gap-2">
                <button className="px-3 py-1.5 text-sm bg-slate-900 text-white rounded" onClick={() => handleSaveSegment({ asNew: false })}>
                  {activeSegmentId ? "Save changes" : "Save segment"}
                </button>
                {activeSegmentId && (
                  <button className="px-3 py-1.5 text-sm border rounded" onClick={() => handleSaveSegment({ asNew: true })}>
                    Save as new
                  </button>
                )}
              </div>
              <button className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded disabled:opacity-60" onClick={launchCampaign} disabled={launching}>
                {launching ? "Launching…" : "Launch campaign"}
              </button>
            </div>
          </div>
        )}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-1">
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="text-sm font-medium text-slate-800">Saved segments</div>
              {activeSegmentId && (
                <button className="text-xs px-2 py-1 border rounded hover:bg-slate-50" onClick={handleDeleteSegment}>
                  Delete
                </button>
              )}
            </div>
            <div className="border rounded-xl overflow-hidden">
              <div className="p-2 border-b bg-white">
                <input
                  className="w-full border rounded px-2 py-1.5 text-sm"
                  placeholder="Search segments"
                  value={segmentSearch}
                  onChange={(e) => setSegmentSearch(e.target.value)}
                />
              </div>
              <div className="max-h-[60vh] overflow-auto divide-y">
                {filteredSegments.map((s) => (
                  <button
                    key={s.id}
                    className={`w-full text-left px-3 py-2 hover:bg-slate-50 ${String(activeSegmentId) === String(s.id) ? "bg-slate-50" : ""}`}
                    onClick={() => {
                      setDsl(String(s.dsl || ""));
                      if (s.store) setStoreId(String(s.store || ""));
                      setActiveSegmentId(String(s.id || ""));
                      setActiveSegmentName(String(s.name || ""));
                      setPageInfo(null);
                      setTimeout(() => preview(), 0);
                    }}
                  >
                    <div className="font-medium text-slate-900 truncate">{s.name || "Segment"}</div>
                    <div className="text-xs text-slate-500 truncate">
                      {s.store ? `${String(s.store)} • ` : ""}
                      {s.description || ""}
                    </div>
                  </button>
                ))}
                {filteredSegments.length === 0 && (
                  <div className="px-3 py-3 text-sm text-slate-500">{segments.length === 0 ? "No segments yet." : "No segments match your search."}</div>
                )}
              </div>
            </div>
          </div>

          <div className="lg:col-span-3 space-y-4">
            <div>
              <div className="text-2xl font-semibold text-slate-900">Customers</div>
              <div className="mt-1 text-sm text-slate-600">
                {typeof segmentCount === "number" ? (
                  <>
                    <span className="font-semibold">
                      {formatInt(segmentCount)}
                      {segmentCountIsEstimate ? "+" : ""}
                    </span>{" "}
                    customers
                    {typeof percentOfBase === "number" && (
                      <>
                        <span className="mx-2 text-slate-300">•</span>
                        <span className="font-semibold">{formatPct(percentOfBase)}</span> of your customer base
                      </>
                    )}
                  </>
                ) : (
                  "—"
                )}
              </div>
              {description && <div className="mt-2 text-sm text-slate-700">{description}</div>}
            </div>

            {err && <div className="text-sm text-rose-700 bg-rose-50 border border-rose-200 px-3 py-2 rounded">{err}</div>}

            {campaignJobId && campaignJob && (
              <div className="border rounded-xl px-3 py-2 text-sm bg-white">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <div className="font-medium">Campaign job</div>
                    <div className="text-xs text-slate-600">Status: {String(campaignJob.status || "")}</div>
                  </div>
                  <div className="text-xs text-slate-600">
                    Sent: {Number(campaignJob.sent || 0)} • Failed: {Number(campaignJob.failed || 0)}
                  </div>
                </div>
                {campaignJob.last_error && <div className="mt-1 text-xs text-rose-700">{String(campaignJob.last_error)}</div>}
              </div>
            )}

            {/* DSL editor */}
            <div className="border rounded-xl overflow-hidden">
              <div className="px-4 py-2 border-b bg-slate-50 text-sm font-medium text-slate-700">Segment definition</div>
              <div className="p-3">
                <textarea className="w-full border rounded px-3 py-2 font-mono text-xs" rows={10} value={dsl} onChange={(e) => setDsl(e.target.value)} />
                {compiledQuery && (
                  <div className="mt-2 text-xs text-slate-600">
                    Compiled query: <span className="font-mono">{compiledQuery}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Criteria chips */}
            {conditions.length > 0 && (
              <div className="border rounded-xl p-3">
                <div className="text-sm font-medium text-slate-800 mb-2">Refine your segment</div>
                <div className="flex flex-wrap gap-2">
                  {conditions.map((c, idx) => (
                    <span key={idx} className="text-xs px-2 py-1 rounded border bg-white text-slate-700 font-mono">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Table */}
            <div className="border rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b flex items-center justify-between">
                <div className="text-sm text-slate-600">
                  {typeof segmentCount === "number" ? <>Showing 50 of {formatInt(segmentCount)} customers</> : "Showing 50 customers"}
                </div>
                <div className="flex items-center gap-2">
                  <button className="px-3 py-1.5 text-sm border rounded" onClick={() => setPageInfo(prevPageInfo)} disabled={!prevPageInfo || loading}>
                    Prev
                  </button>
                  <button className="px-3 py-1.5 text-sm border rounded" onClick={() => setPageInfo(nextPageInfo)} disabled={!nextPageInfo || loading}>
                    Next
                  </button>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-[920px] w-full text-sm">
                  <thead className="bg-slate-50 text-slate-600">
                    <tr>
                      <th className="w-10 px-4 py-2 text-left"> </th>
                      <th className="px-4 py-2 text-left">Customer name</th>
                      <th className="px-4 py-2 text-left">Note</th>
                      <th className="px-4 py-2 text-left">Email subscription</th>
                      <th className="px-4 py-2 text-left">Location</th>
                      <th className="px-4 py-2 text-left">Orders</th>
                      <th className="px-4 py-2 text-left">Amount spent</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {loading && (
                      <tr>
                        <td className="px-4 py-3 text-slate-500" colSpan={7}>
                          Loading…
                        </td>
                      </tr>
                    )}
                    {!loading && customers.length === 0 && (
                      <tr>
                        <td className="px-4 py-3 text-slate-500" colSpan={7}>
                          No customers.
                        </td>
                      </tr>
                    )}
                    {!loading &&
                      customers.map((c) => (
                        <tr key={c.id} className="hover:bg-slate-50">
                          <td className="px-4 py-3">
                            <input type="checkbox" />
                          </td>
                          <td className="px-4 py-3">
                            <div className="font-medium text-slate-900">{c.customer_name || "(no name)"}</div>
                          </td>
                          <td className="px-4 py-3 text-slate-700">{c.note ? String(c.note).slice(0, 80) : ""}</td>
                          <td className="px-4 py-3 text-slate-700">{c.email_subscription_status || "-"}</td>
                          <td className="px-4 py-3 text-slate-700">{c.location || ""}</td>
                          <td className="px-4 py-3 text-slate-700">{typeof c.orders === "number" ? c.orders : 0}</td>
                          <td className="px-4 py-3 text-slate-900 whitespace-nowrap">
                            {c.amount_spent?.currency ? `${c.amount_spent.currency} ${Number(c.amount_spent.value || 0).toFixed(2)}` : ""}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


