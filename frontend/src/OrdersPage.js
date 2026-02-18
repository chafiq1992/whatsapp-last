import React, { useEffect, useState, useCallback, useRef } from "react";
import axios from "axios";

const STATUS_COLORS = {
  Pending: "bg-yellow-100 text-yellow-800",
  Paid: "bg-green-100 text-green-800",
  Refused: "bg-red-100 text-red-800",
  Payout: "bg-blue-100 text-blue-800",
  Archived: "bg-gray-200 text-gray-800",
};

const API_BASE = process.env.REACT_APP_API_BASE || "";

// ─────────────────────────────────────────────────────────────────────────────
// Utility: read/write filter state from query parameters
function loadFilters() {
  const params = new URLSearchParams(window.location.search);
  return {
    start: params.get("start") || "",
    end: params.get("end") || "",
    cities: params.get("cities") ? params.get("cities").split(",") : [],
    status: params.get("status") || "",
    search: params.get("search") || "",
  };
}

function saveFilters(filters) {
  const params = new URLSearchParams();
  if (filters.start) params.set("start", filters.start);
  if (filters.end) params.set("end", filters.end);
  if (filters.cities.length) params.set("cities", filters.cities.join(","));
  if (filters.status) params.set("status", filters.status);
  if (filters.search) params.set("search", filters.search);
  const query = params.toString();
  const url = query ? `?${query}` : window.location.pathname;
  window.history.replaceState(null, "", url);
}

// ─────────────────────────────────────────────────────────────────────────────
export default function OrdersPage() {
  const [filters, setFilters] = useState(loadFilters());
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [orders, setOrders] = useState([]);
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [selected, setSelected] = useState(new Set());
  const loaderRef = useRef(null);

  const resetFilters = () => {
    const fresh = { start: "", end: "", cities: [], status: "", search: "" };
    setFilters(fresh);
    saveFilters(fresh);
    setOrders([]);
    setPage(0);
    setHasMore(true);
  };

  const applyFilters = () => {
    saveFilters(filters);
    setOrders([]);
    setPage(0);
    setHasMore(true);
  };

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const fetchOrders = useCallback(async () => {
    if (!hasMore) return;
    const offset = page * 25;
    const endpoint =
      filters.status === "Archived"
        ? "/archive"
        : filters.status === "Payout"
        ? "/payouts"
        : "/orders";
    try {
      const res = await axios.get(`${API_BASE}${endpoint}`, {
        params: { offset, limit: 25, ...filters },
      });
      const data = res.data || [];
      setOrders((o) => [...o, ...data]);
      setHasMore(data.length === 25);
    } catch (err) {
      console.error("Failed to load orders", err);
    }
  }, [page, filters, hasMore]);

  // Initial load and when filters change
  useEffect(() => {
    fetchOrders();
  }, [fetchOrders]);

  // Infinite scroll observer
  useEffect(() => {
    const el = loaderRef.current;
    if (!el) return;
    const obs = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) {
        setPage((p) => p + 1);
      }
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, [loaderRef]);

  // Keyboard shortcuts for batch actions
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "m" && selected.size) {
        alert(`Marking ${selected.size} orders paid`);
      }
      if (e.key === "e" && selected.size) {
        alert(`Exporting ${selected.size} orders to CSV`);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selected]);

  // ────────────────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-screen overflow-hidden">
      {/* Filter drawer */}
      <div
        className={`fixed inset-0 bg-black bg-opacity-30 z-20 md:static md:translate-x-0 md:bg-transparent ${
          drawerOpen ? "" : "hidden md:block"
        }`}
        onClick={() => setDrawerOpen(false)}
      ></div>
      <div
        className={`fixed z-30 top-0 left-0 h-full w-64 bg-white dark:bg-gray-800 shadow-lg transform transition-transform md:relative md:translate-x-0 ${
          drawerOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        }`}
      >
        <div className="p-4 space-y-4">
          <h2 className="text-lg font-semibold">Filters</h2>
          {/* Date range pills */}
          <div className="flex space-x-2">
            {[
              { label: "Today", start: "today" },
              { label: "7d", start: "7d" },
              { label: "30d", start: "30d" },
            ].map((p) => (
              <button
                key={p.start}
                onClick={() =>
                  setFilters((f) => ({ ...f, start: p.start, end: "" }))
                }
                className={`px-2 py-1 rounded-full border text-sm ${
                  filters.start === p.start ? "bg-blue-500 text-white" : ""
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
          {/* City multi-select */}
          <div>
            <input
              type="text"
              placeholder="Cities"
              value={filters.cities.join(", ")}
              onChange={(e) =>
                setFilters((f) => ({ ...f, cities: e.target.value.split(/\s*,\s*/) }))
              }
              className="w-full border rounded p-1 text-black"
            />
          </div>
          {/* Status chips */}
          <div className="space-x-2">
            {Object.keys(STATUS_COLORS).map((s) => (
              <button
                key={s}
                onClick={() => setFilters((f) => ({ ...f, status: s }))}
                className={`px-2 py-1 rounded-full text-sm border ${
                  filters.status === s ? STATUS_COLORS[s] : ""
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <div className="flex space-x-2">
            <button
              className="flex-1 border rounded p-1"
              onClick={resetFilters}
            >
              Reset
            </button>
            <button
              className="flex-1 bg-blue-500 text-white rounded p-1"
              onClick={applyFilters}
            >
              Apply
            </button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-y-auto" onScroll={(e) => {}}>
        <div className="p-4 md:hidden">
          <button
            onClick={() => setDrawerOpen((o) => !o)}
            className="border px-3 py-1 rounded"
          >
            Filters
          </button>
        </div>
        {/* Batch actions bar */}
        {selected.size > 0 && (
          <div className="p-2 bg-gray-100 dark:bg-gray-700 sticky top-0 z-10 flex space-x-2">
            <button
              onClick={() => alert("Mark Paid")}
              className="px-2 py-1 bg-green-500 text-white rounded"
            >
              Mark Paid
            </button>
            <button
              onClick={() => alert("Export CSV")}
              className="px-2 py-1 bg-blue-500 text-white rounded"
            >
              Export CSV
            </button>
          </div>
        )}
        {/* Grid header for desktop */}
        <div className="hidden md:grid grid-cols-6 font-semibold sticky top-0 bg-white shadow">
          <div className="p-2">Order</div>
          <div className="p-2">Customer</div>
          <div className="p-2">City</div>
          <div className="p-2">Total</div>
          <div className="p-2">Updated</div>
          <div className="p-2">Status</div>
        </div>
        {orders.map((o) => (
          <div
            key={o.order_id}
            className="border-b hover:bg-gray-50 dark:hover:bg-gray-800 grid grid-cols-1 md:grid-cols-6 items-center"
          >
            <div className="p-2 flex items-center space-x-2">
              <input
                type="checkbox"
                className="mr-2"
                checked={selected.has(o.order_id)}
                onChange={() => toggleSelect(o.order_id)}
              />
              <span className="font-mono text-sm">{o.order_id}</span>
            </div>
            <div className="p-2">{o.customer || "-"}</div>
            <div className="p-2">{o.city || "-"}</div>
            <div className="p-2">{o.total ?? ""}</div>
            <div className="p-2">{o.updated_at || o.created_at}</div>
            <div className="p-2">
              <span className={`px-2 py-1 rounded-full text-xs ${STATUS_COLORS[o.status] || ""}`}>{o.status}</span>
            </div>
          </div>
        ))}
        <div ref={loaderRef} className="p-4 text-center text-gray-500">
          {hasMore ? "Loading..." : "No more orders"}
        </div>
      </div>

      {/* Detail drawer */}
      <div className="hidden md:block w-96 border-l border-gray-200 dark:border-gray-700 p-4 overflow-y-auto">
        {/* Placeholder for chat, map and actions */}
        <div className="mb-4">Timeline chat coming soon...</div>
        <div className="mb-4">Map placeholder...</div>
        {orders.find((o) => selected.has(o.order_id) && o.status === "Refused") && (
          <button className="px-3 py-2 bg-red-500 text-white rounded">Request Return</button>
        )}
      </div>
    </div>
  );
}
