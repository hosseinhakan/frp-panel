// FRP Tunnel Suite — panel frontend (Alpine.js + HTMX).
//
// Composition:
//   * FRP.api()        — fetch wrapper over the JSON API (cookie session,
//                        401 → /login redirect, standard {error} envelope).
//   * FRP.sse          — SSE bridge. Primary path: the HTMX sse extension
//                        (hx-ext "sse" owns the EventSource lifecycle incl.
//                        reconnect after the server's deliberate eof), with
//                        Alpine translating the htmx:sseMessage DOM events
//                        into store updates — log text is only ever appended
//                        as text nodes, never innerHTML. If htmx failed to
//                        load, a native EventSource fallback with identical
//                        dispatch keeps the panel usable.
//   * uPlot            — latency + stats history charts, dark-tuned.
//   * Alpine stores    — ui (toasts/confirm), latency (prober feed), logs.
//   * Alpine.data      — one component per view, mounted on demand by the
//                        shell's <template x-if> routing. Components register
//                        teardown callbacks with FRP.cleanup(), which the
//                        shell runs when switching views (Alpine 3.14 has no
//                        component-destroy hook).
"use strict";

/* ============================================================================
 * Utilities
 * ========================================================================== */

window.FRP = {
  async api(path, opts = {}) {
    const init = {
      method: opts.method || "GET",
      headers: {},
      credentials: "same-origin",
    };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    } else if (opts.form !== undefined) {
      init.body = opts.form; // browser sets the multipart boundary
    }
    let resp;
    try {
      resp = await fetch(path, init);
    } catch {
      throw new Error("network error — is the panel reachable?");
    }
    if (resp.status === 401 && !location.pathname.startsWith("/login")) {
      location.href = "/login";
      throw new Error("authentication required");
    }
    if (opts.raw) return resp;
    let data = {};
    try {
      data = await resp.json();
    } catch {
      /* non-JSON error body */
    }
    if (!resp.ok) {
      const err = new Error(data.error || resp.statusText || "request failed");
      err.status = resp.status;
      err.data = data;
      throw err;
    }
    return data;
  },

  // genToken returns a 32-char [A-Za-z0-9] token (crypto.getRandomValues,
  // rejection-sampled) — the same shape frpconf.RandomToken produces.
  genToken() {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const out = [];
    const buf = new Uint32Array(32);
    const limit = Math.floor(0x100000000 / alphabet.length) * alphabet.length;
    let i = 32;
    while (out.length < 32) {
      if (i === 32) {
        crypto.getRandomValues(buf);
        i = 0;
      }
      if (buf[i] < limit) out.push(alphabet[buf[i] % alphabet.length]);
      i++;
    }
    return out.join("");
  },

  // copy puts text on the clipboard. navigator.clipboard needs a secure
  // context — the panel is often reached over plain http://<tunnel-ip> — so
  // fall back to a temporary textarea + execCommand.
  async copy(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      /* fall through */
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-100px";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  },

  fmtBytes(n) {
    if (n === undefined || n === null || isNaN(n)) return "—";
    if (n < 1024) return n + " B";
    const units = ["KiB", "MiB", "GiB", "TiB"];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i];
  },

  fmtUptime(seconds) {
    if (seconds === undefined || seconds === null || seconds < 0) return "—";
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    if (m > 0) return m + "m";
    return seconds + "s";
  },

  // fmtAddr renders host:port, bracketing IPv6 literals.
  fmtAddr(host, port) {
    const h = host || "?";
    const p = port === undefined || port === null || port === "" ? "?" : port;
    return h.includes(":") && !h.startsWith("[") ? "[" + h + "]:" + p : h + ":" + p;
  },

  fmtRtt(ms) {
    if (ms === undefined || ms === null || ms <= 0) return "—";
    return ms >= 100 ? ms.toFixed(0) + " ms" : ms.toFixed(1) + " ms";
  },

  // versionLabel normalizes "1.2.2", "v1.2.2", or "vv1.2.2" to "v1.2.2".
  versionLabel(version) {
    const v = String(version || "").trim().replace(/^v+/i, "");
    return v ? "v" + v : "v—";
  },

  // unitLabel hides systemd's internal "unknown" in favour of the state a
  // human expects: stopped / disabled.
  unitLabel(state, kind) {
    const s = String(state || "").trim().toLowerCase();
    if (kind === "enabled") {
      return !s || s === "unknown" || s === "not-found" ? "disabled" : s;
    }
    if (!s || s === "unknown" || s === "not-found" || s === "dead" || s === "inactive") {
      return "stopped";
    }
    return s;
  },

  // unitPill maps a systemctl state onto a pill class.
  unitPill(state) {
    switch ((state || "").trim()) {
      case "active":
        return "ok";
      case "inactive":
        return "idle";
      case "failed":
        return "bad";
      case "enabled":
        return "ok";
      case "disabled":
        return "idle";
      case "activating":
      case "reloading":
        return "warn";
      default:
        return "warn";
    }
  },

  debounce(fn, ms) {
    let t;
    return function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), ms);
    };
  },
};

/* ============================================================================
 * View-switch teardown registry (no destroy hook in Alpine 3.14)
 * ========================================================================== */

FRP._cleanup = [];
FRP.cleanup = function (fn) {
  FRP._cleanup.push(fn);
};
FRP.runCleanup = function () {
  while (FRP._cleanup.length) {
    try {
      FRP._cleanup.pop()();
    } catch (e) {
      console.warn("cleanup failed", e);
    }
  }
};

/* ============================================================================
 * SSE bridge (htmx sse extension primary, native fallback)
 *
 * htmx's sse extension owns the EventSource lifecycle (creation, reconnect
 * after the server's deliberate eof/overflow, cleanup when the element goes
 * away). Payload delivery bypasses its DOM events entirely: htmx triggers
 * "htmx:sseMessage" (camelCase), but HTML attribute names lowercase, so
 * Alpine listeners registered via @htmx:sseMessage never match. Instead we
 * wrap htmx.createEventSource — the documented factory the sse extension
 * calls for every (re)connection — and attach direct listeners that feed
 * the stores. Log text is only ever appended as text nodes, never
 * innerHTML.
 * ========================================================================== */

FRP.sse = (function () {
  const natives = new Map(); // el → EventSource (no-htmx fallback)
  const handlers = new Map(); // url → {dispatch, names:Set}
  let hooked = false;

  function tap(es, entry) {
    // addEventListener (not the .on* properties): the sse extension assigns
    // its own .onopen/.onerror for reconnect handling, which would clobber
    // property-based taps. Listener stacks coexist with both.
    es.addEventListener("open", () => entry.dispatch({ kind: "open" }));
    es.addEventListener("error", () => entry.dispatch({ kind: "error" }));
    es.addEventListener("message", (ev) => entry.dispatch({ kind: "data", type: "message", data: ev.data }));
    for (const name of entry.names) {
      es.addEventListener(name, (ev) => entry.dispatch({ kind: "data", type: name, data: ev.data }));
    }
  }

  function ensureHook() {
    if (hooked || !window.htmx) return;
    hooked = true;
    const base = htmx.createEventSource.bind(htmx);
    htmx.createEventSource = function (url) {
      const es = base(url);
      const entry = handlers.get(url);
      if (entry && es) tap(es, entry);
      return es;
    };
  }

  return {
    // connect(el, url, {names, onEvent}) — names lists the SSE event names
    // to listen for in addition to unnamed "message" events.
    connect(el, url, opts = {}) {
      this.disconnect(el);
      const dispatch = opts.onEvent || function () {};
      const names = new Set(opts.names || []);
      ensureHook();
      if (window.htmx) {
        handlers.set(url, { dispatch, names });
        el.setAttribute("sse-connect", url);
        htmx.process(el);
      } else {
        const es = new EventSource(url, { withCredentials: true });
        natives.set(el, es);
        tap(es, { dispatch, names });
      }
    },
    disconnect(el) {
      if (!el) return;
      if (window.htmx) {
        const url = el.getAttribute && el.getAttribute("sse-connect");
        if (url) handlers.delete(url);
        try {
          htmx.trigger(el, "htmx:beforeCleanupElement");
        } catch {
          /* element may already be detached */
        }
      }
      const es = natives.get(el);
      if (es) {
        es.close();
        natives.delete(el);
      }
    },
  };
})();

/* ============================================================================
 * uPlot dark theme helper
 * ========================================================================== */

FRP.chart = (function () {
  const palette = [
    "#22d3ee", "#34d399", "#fbbf24", "#a78bfa", "#38bdf8", "#fb7185", "#a3e635", "#fb923c",
  ];
  const grid = "#27272a";
  const label = "#8b8b96";

  function lineSeries(i, extra) {
    return Object.assign(
      {
        label: "series " + (i + 1),
        stroke: palette[i % palette.length],
        width: 1.5,
        points: { show: false },
        spanGaps: false,
      },
      extra || {}
    );
  }

  function baseOpts(width, height, series) {
    return {
      width,
      height,
      legend: { show: true, live: 2 },
      cursor: { drag: { x: false, y: false } },
      series,
      axes: [
        {
          grid: { show: true, stroke: grid, width: 1 },
          ticks: { show: false },
          values: "{HH}:{mm}:{ss}",
          stroke: label,
          font: '11px ui-monospace, Consolas, monospace',
          space: 60,
        },
        {
          grid: { show: true, stroke: grid, width: 1, dash: [3, 3] },
          ticks: { show: false },
          stroke: label,
          font: '11px ui-monospace, Consolas, monospace',
          size: 52,
        },
      ],
    };
  }

  return {
    available() {
      return typeof uPlot !== "undefined";
    },
    // create(containerEl, height, seriesDefs) → handle or null.
    // seriesDefs: array of {label, stroke?, fill?} (index 0 = x axis).
    create(containerEl, height, seriesDefs) {
      if (!this.available() || !containerEl) return null;
      containerEl.innerHTML = "";
      const defs = seriesDefs || [{}];
      const series = [
        {},
        ...defs.slice(1).map((d, i) =>
          lineSeries(i, {
            label: d.label || "series " + (i + 1),
            ...(d.stroke ? { stroke: d.stroke } : {}),
            ...(d.fill ? { fill: d.fill } : {}),
          })
        ),
      ];
      const width = Math.max(220, containerEl.clientWidth - 12);
      const opts = baseOpts(width, height || 260, series);
      const uplot = new uPlot(opts, [[], ...series.slice(1).map(() => [])], containerEl);
      const onResize = FRP.debounce(() => {
        if (!containerEl.isConnected) {
          window.removeEventListener("resize", onResize);
          return;
        }
        uplot.setSize({ width: Math.max(220, containerEl.clientWidth - 12), height: opts.height });
      }, 200);
      window.addEventListener("resize", onResize);
      return {
        uplot,
        set(data) {
          uplot.setData(data, false);
        },
        destroy() {
          window.removeEventListener("resize", onResize);
          uplot.destroy();
        },
      };
    },
    palette,
  };
})();

/* ============================================================================
 * Alpine stores + view components
 * ========================================================================== */

document.addEventListener("alpine:init", () => {
  /* ---- store: ui (toasts + confirm dialog) -------------------------------- */

  Alpine.store("ui", {
    toasts: [],
    _seq: 0,
    push(msg, kind) {
      const id = ++this._seq;
      this.toasts.push({ id, msg, kind: kind || "ok" });
      setTimeout(() => this.dismiss(id), 5600);
    },
    dismiss(id) {
      this.toasts = this.toasts.filter((t) => t.id !== id);
    },
    confirm(opts) {
      return new Promise((resolve) => {
        this.confirmState = {
          open: true,
          title: opts.title || "Are you sure?",
          message: opts.message || "",
          confirmText: opts.confirmText || "Confirm",
          danger: !!opts.danger,
        };
        this._resolve = resolve;
      });
    },
    confirmState: { open: false, title: "", message: "", confirmText: "Confirm", danger: false },
    _resolve: null,
    answer(v) {
      this.confirmState.open = false;
      if (this._resolve) {
        this._resolve(v);
        this._resolve = null;
      }
    },
  });

  /* ---- store: latency (prober SSE feed) ----------------------------------- */

  Alpine.store("latency", {
    connected: false,
    lastTs: 0,
    targets: {}, // id → {kind, host, ok, rtt_ms, loss_pct, samples, hist:[[ts,rtt]…]}
    order: [],
    intervalSec: 5,
    HIST_CAP: 900, // 75 min at 5 s ticks

    onEvent(kind, type, data) {
      if (kind === "open") {
        this.connected = true;
        return;
      }
      if (kind === "error") {
        this.connected = false;
        return;
      }
      let snap;
      try {
        snap = JSON.parse(data);
      } catch {
        return;
      }
      if (!snap || !snap.targets) return;
      this.lastTs = snap.ts || Math.floor(Date.now() / 1000);
      if (snap.interval_seconds) this.intervalSec = snap.interval_seconds;
      for (const [id, st] of Object.entries(snap.targets)) {
        let t = this.targets[id];
        if (!t) {
          t = this.targets[id] = {
            kind: st.kind, host: st.host || "", ok: false, rtt_ms: 0,
            loss_pct: 0, samples: 0, hist: [],
          };
          this.order.push(id);
          this.order.sort();
        }
        t.ok = !!st.ok;
        t.rtt_ms = st.rtt_ms || 0;
        t.loss_pct = st.loss_pct || 0;
        t.samples = st.samples || 0;
        if (type === "sample" || t.hist.length === 0) {
          t.hist.push([this.lastTs, st.ok ? st.rtt_ms || 0 : null]);
          if (t.hist.length > this.HIST_CAP) t.hist.shift();
        }
      }
    },

    clear() {
      this.targets = {};
      this.order = [];
    },

    // chartData() shapes the ring buffers for uPlot: aligned x + one y per id.
    chartData() {
      if (!this.order.length) return null;
      const first = this.targets[this.order[0]];
      const xs = first.hist.map((p) => p[0]);
      const data = [xs];
      for (const id of this.order) {
        const hist = this.targets[id].hist;
        const ys = new Array(xs.length).fill(null);
        let j = 0;
        for (let i = 0; i < xs.length && j < hist.length; i++) {
          while (j < hist.length && hist[j][0] < xs[i]) j++;
          if (j < hist.length && hist[j][0] === xs[i]) ys[i] = hist[j][1];
        }
        data.push(ys);
      }
      return data;
    },
  });

  /* ---- store: logs (journal SSE feed) -------------------------------------- */

  Alpine.store("logs", {
    connected: false,
    streamNote: "",
    lines: [], // {ts, text, cls}
    paused: false,
    filter: "all", // all | warn | error
    LINES_CAP: 4000,

    reset() {
      this.lines = [];
      this.streamNote = "";
    },
    onEvent(kind, type, data) {
      if (kind === "open") {
        this.connected = true;
        this.streamNote = "";
        return;
      }
      if (kind === "error") {
        this.connected = false;
        this.streamNote = "stream lost — reconnecting…";
        return;
      }
      if (type === "eof") {
        this.connected = false;
        this.streamNote = "stream ended — reconnecting for a fresh tail…";
        return;
      }
      if (type === "overflow") {
        this.connected = false;
        this.streamNote = "log volume exceeded the stream window — reconnecting…";
        return;
      }
      if (this.paused) return;
      let text = data;
      let ts = "";
      let cls = "";
      // journalctl short-iso: "2026-11-20T12:34:56+0000 host unit[pid]: msg"
      const sp = text.indexOf(" ");
      if (sp > 0 && /^\d{4}-\d{2}-\d{2}T/.test(text)) {
        ts = text.slice(0, sp);
        text = text.slice(sp + 1);
      }
      const low = text.toLowerCase();
      if (/\b(error|fail|crit|emerg|alert|fatal|denied)\b/.test(low)) cls = "lvl-err";
      else if (/\b(warn|degrad|timeout)\b/.test(low)) cls = "lvl-warn";
      this.lines.push({ ts, text, cls });
      if (this.lines.length > this.LINES_CAP) {
        this.lines.splice(0, this.lines.length - this.LINES_CAP);
      }
    },
    visible() {
      if (this.filter === "all") return this.lines;
      const want = this.filter === "error" ? "lvl-err" : "lvl-warn";
      return this.lines.filter((l) => l.cls === want);
    },
  });

  /* ---- component: shell (routing + session + confirm modal + toasts) ------ */

  Alpine.data("shell", () => ({
    view: "dashboard",
    me: null,
    health: { version: FRP.version, uptime_seconds: 0 },
    views: [
      { id: "dashboard", label: "Dashboard", ico: "◉", group: 0 },
      { id: "servers", label: "FRP Servers", ico: "▤", group: 1 },
      { id: "clients", label: "FRP Clients", ico: "▥", group: 1 },
      { id: "gre", label: "GRE Tunnels", ico: "⇄", group: 1 },
      { id: "turbo", label: "Turbo", ico: "⚡", group: 2 },
      { id: "logs", label: "Logs", ico: "≡", group: 2 },
      { id: "stats", label: "Stats", ico: "∿", group: 2 },
      { id: "backup", label: "Backup", ico: "⛁", group: 2 },
      { id: "watchdog", label: "Watchdog", ico: "♥", group: 2 },
    ],
    navGroups: [
      { label: "Overview", filter: 0 },
      { label: "Tunnels & FRP", filter: 1 },
      { label: "System", filter: 2 },
    ],

    async init() {
      const applyHash = () => {
        const h = (location.hash || "").replace(/^#/, "");
        if (h && this.views.some((v) => v.id === h)) this.view = h;
      };
      applyHash();
      window.addEventListener("hashchange", applyHash);

      try {
        this.me = await FRP.api("/api/auth/me");
      } catch {
        return; // api() already redirected to /login
      }
      this.loadHealth();
      const t = setInterval(() => {
        if (!this.$root.isConnected) {
          clearInterval(t);
          return;
        }
        this.loadHealth();
      }, 30000);
      FRP.cleanup(() => clearInterval(t));

      // Global latency prober feed — owned by the shell, shared by views.
      const el = document.getElementById("sse-latency");
      if (el) {
        FRP.sse.connect(el, "/api/monitor/latency/stream", {
          names: ["snapshot", "sample"],
          onEvent: (ev) => this.$store.latency.onEvent(ev.kind, ev.type, ev.data),
        });
        FRP.cleanup(() => FRP.sse.disconnect(el));
      }
    },

    nav(view) {
      if (this.view === view) return;
      FRP.runCleanup();
      this.view = view;
      history.replaceState(null, "", "#" + view);
    },

    async loadHealth() {
      try {
        this.health = await FRP.api("/api/health");
      } catch {
        this.health = { version: "—", uptime_seconds: 0 };
      }
    },

    viewsInGroup(g) {
      return this.views.filter((v) => v.group === g);
    },

    async logout() {
      try {
        await FRP.api("/api/auth/logout", { method: "POST" });
      } catch {
        /* ignore */
      }
      location.href = "/login";
    },
  }));

  /* ---- component: dashboard ------------------------------------------------ */

  Alpine.data("dashboardView", () => ({
    services: [],
    stats: [],
    turbo: null,
    watchdog: null,
    loading: true,
    chart: null,
    _sig: "",
    rev: null,

    async init() {
      await this.loadAll();
      this.$nextTick(() => this.syncChart(true));
      // Smooth chart updates: every prober tick re-feeds uPlot.
      this.$watch("$store.latency.lastTs", () => this.syncChart(false));
      const t = setInterval(() => {
        if (!this.$root.isConnected) {
          clearInterval(t);
          return;
        }
        this.loadAll();
      }, 10000);
      FRP.cleanup(() => {
        clearInterval(t);
        if (this.chart) {
          this.chart.destroy();
          this.chart = null;
        }
      });
    },

    async loadAll() {
      const jobs = await Promise.allSettled([
        FRP.api("/api/services"),
        FRP.api("/api/stats"),
        FRP.api("/api/system/turbo"),
        FRP.api("/api/watchdog"),
      ]);
      if (jobs[0].status === "fulfilled") this.services = jobs[0].value.services || [];
      if (jobs[1].status === "fulfilled") this.stats = jobs[1].value.instances || [];
      if (jobs[2].status === "fulfilled") this.turbo = jobs[2].value;
      if (jobs[3].status === "fulfilled") this.watchdog = jobs[3].value;
      this.loading = false;
    },

    // syncChart recreates uPlot when the target set changes, then pushes data.
    syncChart(force) {
      const el = this.$refs.chart;
      if (!el || !FRP.chart.available()) return;
      const store = this.$store.latency;
      const sig = store.order.join("|");
      if (force || sig !== this._sig) {
        this._sig = sig;
        if (this.chart) {
          this.chart.destroy();
          this.chart = null;
        }
        this.chart = FRP.chart.create(
          el,
          250,
          store.order.map((id) => ({ label: id }))
        );
      }
      if (!this.chart) return;
      const data = store.chartData();
      this.chart.set(data || [[], []]);
    },

    get svcGroups() {
      const groups = [
        { label: "frps servers", match: (u) => u.startsWith("frps@"), items: [] },
        { label: "frpc clients", match: (u) => u.startsWith("frpc@"), items: [] },
        { label: "GRE tunnels", match: (u) => u.startsWith("gre-tunnel@"), items: [] },
        { label: "system units", match: (u) => !u.includes("@"), items: [] },
      ];
      for (const s of this.services) {
        for (const g of groups) if (g.match(s.unit)) g.items.push(s);
      }
      return groups.filter((g) => g.items.length);
    },

    get statsUp() {
      return this.stats.filter((s) => s.up);
    },
    get totalConns() {
      return this.stats.reduce((acc, s) => acc + (s.cur_conns || 0), 0);
    },
    get totalIn() {
      return this.stats.reduce((acc, s) => acc + (s.total_traffic_in || 0), 0);
    },
    get totalOut() {
      return this.stats.reduce((acc, s) => acc + (s.total_traffic_out || 0), 0);
    },
    get turboOn() {
      return !!this.turbo && this.turbo.dropin === "installed";
    },
    get zramOn() {
      return !!(this.turbo && this.turbo.zram && this.turbo.zram.active);
    },

    pillFor(state) {
      return FRP.unitPill(state);
    },

    async unitAction(unit, action) {
      try {
        await FRP.api(`/api/services/${encodeURIComponent(unit)}/action`, {
          method: "POST",
          body: { action },
        });
        this.$store.ui.push(`${action} ${unit} — done`, "ok");
      } catch (e) {
        this.$store.ui.push(`${action} ${unit}: ${e.message}`, "bad");
      }
      this.loadAll();
    },

    /* ---- FRP over GRE Reverse quick-setup wizard ------------------------- */

    blankRev(role) {
      const foreign = role === "foreign";
      return {
        step: role ? "form" : "role",
        role: role || "",
        iranPublicIp: "",
        foreignPublicIp: "",
        iface: foreign ? "" : "gt11",
        subnet: foreign ? "" : "10.100.111.0/30",
        controlPort: foreign ? "" : 7025,
        protocol: foreign ? "" : "tcp",
        bindAddr: "", // empty = bind to the allocated GRE tunnel IP
        mirrorPayload: "",
        localPorts: "8989,8443,2053",
        proto: "both",
        localIp: "127.0.0.1",
        clientName: "",
        token: "",
        rawSpeed: true,
        encryptTls: false,
        foreignPorts: "8989",
        foreignProto: "tcp",
        foreignRawSpeed: true,
        foreignBusy: false,
        foreignError: "",
        enableWatchdog: true,
        busy: false,
        error: "",
        result: null,
      };
    },

    openRevWizard() {
      this.rev = this.blankRev("");
      this.loadRevDefaults();
    },

    // Pre-fill the Iran form with the next free iface/subnet/port so a host
    // that already runs tunnels does not start with a guaranteed conflict.
    async loadRevDefaults() {
      try {
        const d = await FRP.api("/api/wizard/gre-frp/defaults");
        if (!this.rev || this.rev.role !== "iran") return;
        if (d.iface) this.rev.iface = d.iface;
        if (d.subnet) this.rev.subnet = d.subnet;
        if (d.controlPort) this.rev.controlPort = d.controlPort;
      } catch {
        /* non-fatal: the server still auto-allocates on submit */
      }
    },

    revPickRole(role) {
      const keepWatchdog = this.rev ? this.rev.enableWatchdog : true;
      this.rev = this.blankRev(role);
      this.rev.enableWatchdog = keepWatchdog;
      if (role === "iran") this.loadRevDefaults();
    },

    // The mirror payload is the source of truth for the Foreign TLS mode: a
    // TLS-forced Iran frps cannot accept a plain frpc.
    revTLSFromPayload(text) {
      const m = /^\s*TLS_ENABLE\s*=\s*(true|false)\s*$/im.exec(String(text || ""));
      return m ? m[1].toLowerCase() === "true" : null;
    },

    revSyncTLS() {
      if (!this.rev) return;
      const v = this.revTLSFromPayload(this.rev.mirrorPayload);
      if (v !== null) this.rev.encryptTls = v;
    },

    async revRun() {
      const r = this.rev;
      if (!r) return;
      r.busy = true;
      r.error = "";
      let body;
      if (r.role === "iran") {
        body = {
          role: "iran",
          iranPublicIp: r.iranPublicIp.trim(),
          foreignPublicIp: r.foreignPublicIp.trim(),
          iface: r.iface.trim(),
          subnet: r.subnet.trim(),
          controlPort: Number(r.controlPort) || 0,
          protocol: r.protocol,
          bindAddr: r.bindAddr,
          token: r.token.trim(),
          encrypt_tls: !!r.encryptTls,
          enableWatchdog: !!r.enableWatchdog,
        };
      } else {
        this.revSyncTLS();
        // With a payload, only send fields the user actually filled in —
        // otherwise UI defaults would override the pasted tunnel params.
        body = {
          role: "foreign",
          mirrorPayload: r.mirrorPayload.trim(),
          localPorts: r.localPorts.trim(),
          proto: r.proto,
          localIp: r.localIp.trim(),
          clientName: r.clientName.trim(),
          rawSpeed: !!r.rawSpeed,
          encrypt_tls: !!r.encryptTls,
          enableWatchdog: !!r.enableWatchdog,
        };
        if (r.foreignPublicIp.trim()) body.foreignPublicIp = r.foreignPublicIp.trim();
        if (r.iranPublicIp.trim()) body.iranPublicIp = r.iranPublicIp.trim();
        if (r.token.trim()) body.token = r.token.trim();
        if (r.iface.trim()) body.iface = r.iface.trim();
        if (r.controlPort !== "" && Number(r.controlPort) > 0) body.controlPort = Number(r.controlPort);
        if (r.protocol) body.protocol = r.protocol;
      }
      try {
        r.result = await FRP.api("/api/wizard/gre-frp", { method: "POST", body });
        r.step = "result";
        this.$store.ui.push(
          r.role === "iran"
            ? "Iran entry node ready — copy the mirror payload to the Foreign node"
            : "Foreign exit node ready — see the link test",
          "ok"
        );
        this.loadAll();
      } catch (e) {
        r.error = e.message;
      }
      r.busy = false;
    },

    async revGenForeign() {
      const r = this.rev;
      if (!r || !r.result || r.role !== "iran") return;
      r.foreignBusy = true;
      r.foreignError = "";
      try {
        const d = await FRP.api(
          `/api/servers/${encodeURIComponent(r.result.server.name)}/foreign-script`,
          {
            method: "POST",
            body: {
              foreignPublicIp: r.foreignPublicIp.trim(),
              iranPublicIp: r.iranPublicIp.trim(),
              iface: r.iface.trim(),
              ports: r.foreignPorts.trim(),
              proto: r.foreignProto,
              localIp: "127.0.0.1",
              rawSpeed: !!r.foreignRawSpeed,
              encrypt_tls: !!r.encryptTls,
            },
          }
        );
        r.result.foreign_script = d.script;
      } catch (e) {
        r.foreignError = e.message;
      }
      r.foreignBusy = false;
    },

    async revCopy(text) {
      const ok = await FRP.copy(text || "");
      this.$store.ui.push(
        ok ? "copied to clipboard" : "copy failed — select the text manually",
        ok ? "ok" : "warn"
      );
    },
  }));

  /* ---- component: servers --------------------------------------------------- */

  Alpine.data("serversView", () => ({
    rows: [],
    loading: true,
    greIPs: [],
    tunnels: [],
    wizDefaults: null,

    wiz: null,
    edit: null,
    raw: null,
    regen: null,
    once: null,
    foreign: null,

    async init() {
      await this.load();
      FRP.api("/api/gre")
        .then((d) => {
          this.tunnels = d.tunnels || [];
          this.greIPs = this.tunnels
            .map((t) => (t.local_private_ip || "").split("/")[0])
            .filter(Boolean);
        })
        .catch(() => {});
      FRP.api("/api/wizard/defaults")
        .then((d) => {
          this.wizDefaults = d;
        })
        .catch(() => {});
    },

    async load() {
      try {
        const d = await FRP.api("/api/servers");
        this.rows = d.servers || [];
      } catch (e) {
        this.$store.ui.push("cannot list servers: " + e.message, "bad");
      }
      this.loading = false;
    },

    // bindChoices feeds the editable datalist. The bind field itself is a
    // plain text input, so any current value (0.0.0.0, ::, a GRE IP or a
    // custom address) round-trips exactly and is never silently replaced.
    bindChoices() {
      return [
        { v: "::", label: ":: — dual-stack (recommended)" },
        { v: "0.0.0.0", label: "0.0.0.0 — IPv4 only" },
        ...this.greIPs.map((ip) => ({ v: ip, label: ip + " — GRE tunnel IP" })),
      ];
    },

    openCreate() {
      this.wiz = {
        name: "",
        bindPort: 7000,
        bindAddr: "::",
        protocol: "quic",
        tcpMux: false,
        tlsForce: false,
        token: FRP.genToken(),
        genToken: true,
        webEnabled: true,
        busy: false,
        error: "",
      };
    },

    async create() {
      const w = this.wiz;
      if (!w) return;
      w.busy = true;
      w.error = "";
      try {
        const resp = await FRP.api("/api/servers", {
          method: "POST",
          body: {
            name: w.name.trim() || undefined,
            bindPort: Number(w.bindPort),
            bindAddr: w.bindAddr.trim(),
            protocol: w.protocol,
            tcpMux: w.tcpMux,
            tlsForce: !!w.tlsForce,
            token: w.genToken ? w.token : "",
            webEnabled: w.webEnabled,
          },
        });
        this.wiz = null;
        this.once = {
          title: `frps@${resp.name} created`,
          token: resp.token || "(custom token in use)",
          webPort: resp.webPort,
          webUser: resp.webUser,
          webPassword: resp.webPassword,
          backup: resp.backup,
          verify: resp.verify,
          note: resp.unit_error ? "unit start failed: " + resp.unit_error : "",
        };
        this.load();
      } catch (e) {
        w.error = e.message;
        w.busy = false;
      }
    },

    async openEdit(row) {
      const name = row.name;
      try {
        // Template / unparseable configs can only be edited as raw TOML.
        if ((row.style || "managed") !== "managed") {
          await this.openRaw(name);
          return;
        }
        const d = await FRP.api(`/api/servers/${encodeURIComponent(name)}`);
        const c = d.config || {};
        const style = d.style || c.style || row.style || "managed";
        if (style !== "managed") {
          await this.openRaw(name);
          return;
        }
        this.edit = {
          name,
          style,
          bindPort: c.bindPort || 7000,
          bindAddr: c.bindAddr || "::", // exact value — never a preset guess
          // frps binds the forwarded user ports here. Empty means "same as
          // bindAddr"; for a GRE/private bindAddr that would make the ports
          // unreachable publicly, so default to 0.0.0.0.
          proxyBindAddr:
            c.proxyBindAddr !== undefined && c.proxyBindAddr !== ""
              ? c.proxyBindAddr
              : ["", "0.0.0.0", "::"].includes(c.bindAddr || "")
              ? ""
              : "0.0.0.0",
          protocol: c.protocol === "tcp" ? "none" : c.protocol || "quic",
          token: d.token || "",
          tcpMux: !!c.tcpMux,
          tlsForce: !!c.tlsForce,
          tcpMuxKeepaliveInterval: c.tcpMuxKeepaliveInterval || 10,
          heartbeatTimeout: c.heartbeatTimeout || 25,
          tcpKeepalive: c.tcpKeepalive || 15,
          maxPoolCount: c.maxPoolCount || 65535,
          quicKeepalivePeriod: c.quicKeepalivePeriod || 10,
          quicMaxIdleTimeout: c.quicMaxIdleTimeout || 30,
          quicMaxIncomingStreams: c.quicMaxIncomingStreams || 100000,
          restart: !!((d.unit || c.unit) && (d.unit || c.unit).active === "active"),
          busy: false,
          error: "",
        };
      } catch (e) {
        this.$store.ui.push(`cannot open ${name}: ${e.message}`, "bad");
      }
    },

    async saveEdit() {
      const e = this.edit;
      if (!e) return;
      e.busy = true;
      e.error = "";
      try {
        const d = await FRP.api(`/api/servers/${encodeURIComponent(e.name)}`, {
          method: "PUT",
          body: {
            bindPort: Number(e.bindPort),
            bindAddr: e.bindAddr.trim(),
            proxyBindAddr: (e.proxyBindAddr || "").trim(),
            protocol: e.protocol,
            tcpMux: e.tcpMux,
            tlsForce: !!e.tlsForce,
            tcpMuxKeepaliveInterval: Number(e.tcpMuxKeepaliveInterval) || 0,
            heartbeatTimeout: Number(e.heartbeatTimeout) || 25,
            tcpKeepalive: Number(e.tcpKeepalive) || 15,
            maxPoolCount: Number(e.maxPoolCount) || 65535,
            quicKeepalivePeriod: Number(e.quicKeepalivePeriod) || 10,
            quicMaxIdleTimeout: Number(e.quicMaxIdleTimeout) || 30,
            quicMaxIncomingStreams: Number(e.quicMaxIncomingStreams) || 100000,
            restart: !!e.restart,
            ...(e.token.trim() ? { token: e.token.trim() } : {}),
          },
        });
        this.$store.ui.push(
          `saved — verify: ${d.verify}, backup: ${d.backup || "n/a"}`,
          "ok"
        );
        this.edit = null;
        this.load();
      } catch (err) {
        if (/raw|TOML/i.test(err.message)) {
          this.edit = null;
          await this.openRaw(e.name);
          this.$store.ui.push(err.message, "warn");
          return;
        }
        e.error = err.message;
        e.busy = false;
      }
    },

    retoken() {
      if (this.edit) this.edit.token = FRP.genToken();
    },

    /* ---- one-click Foreign installer ---------------------------------- */

    ipOf(cidr) {
      return String(cidr || "").split("/")[0];
    },

    openForeign(row) {
      const linked =
        this.tunnels.find(
          (t) =>
            this.ipOf(t.local_private_ip) === row.bindAddr ||
            this.ipOf(t.remote_private_ip) === row.bindAddr
        ) || (this.tunnels.length === 1 ? this.tunnels[0] : null);
      const dflt = this.wizDefaults || {};
      // The linked tunnel carries the zero-drop profile; show exactly what the
      // generated script will write so the Foreign node cannot drift.
      const mtu = linked && linked.mtu ? linked.mtu : 1280;
      const mssMode = linked && linked.mss_mode ? linked.mss_mode : "1220";
      const txqueuelen = linked && linked.txqueuelen ? linked.txqueuelen : 1000;
      const bindAddr = String(row.bindAddr || "");
      const explicitProxy = String(row.proxyBindAddr || "");
      const effectiveProxy =
        explicitProxy !== ""
          ? explicitProxy
          : ["", "0.0.0.0", "::"].includes(bindAddr)
          ? bindAddr || "::"
          : "0.0.0.0";
      const proxyBindOk = effectiveProxy === "0.0.0.0" || effectiveProxy === "::";
      this.foreign = {
        row,
        linked: !!linked,
        iface: linked ? linked.iface : dflt.iface || "gt11",
        iranPublicIp: linked ? linked.local_public_ip : "",
        foreignPublicIp: linked ? linked.remote_public_ip : "",
        ports: "8989",
        proto: "tcp",
        localIp: "127.0.0.1",
        subnet: linked ? "" : dflt.subnet || "",
        mtu,
        mssMode,
        txqueuelen,
        proxyBindAddr: effectiveProxy,
        proxyBindOk,
        rawSpeed: true,
        encryptTls: !!row.tlsForce,
        busy: false,
        error: "",
        result: null,
      };
      // A linked tunnel already knows the Foreign public IP: generate right away.
      if (this.foreign.foreignPublicIp) this.genForeign();
    },

    async genForeign() {
      const f = this.foreign;
      if (!f) return;
      f.busy = true;
      f.error = "";
      try {
        const d = await FRP.api(
          `/api/servers/${encodeURIComponent(f.row.name)}/foreign-script`,
          {
            method: "POST",
            body: {
              foreignPublicIp: f.foreignPublicIp.trim(),
              iranPublicIp: f.iranPublicIp.trim(),
              iface: f.iface.trim(),
              subnet: f.subnet.trim(),
              ports: f.ports.trim(),
              proto: f.proto,
              localIp: f.localIp.trim(),
              rawSpeed: !!f.rawSpeed,
              encrypt_tls: !!f.encryptTls,
            },
          }
        );
        f.result = d;
      } catch (e) {
        f.error = e.message;
      }
      f.busy = false;
    },

    async openRaw(name) {
      try {
        const d = await FRP.api(`/api/servers/${encodeURIComponent(name)}/raw`);
        this.raw = { name, style: d.style, content: d.content, busy: false, error: "", saved: "" };
      } catch (e) {
        this.$store.ui.push(name + ": " + e.message, "bad");
      }
    },

    async saveRaw() {
      const r = this.raw;
      if (!r) return;
      r.busy = true;
      r.error = "";
      try {
        const d = await FRP.api(`/api/servers/${encodeURIComponent(r.name)}/raw`, {
          method: "PUT",
          body: { content: r.content },
        });
        r.saved = `saved — verify: ${d.verify}, backup: ${d.backup || "n/a"}`;
        this.load();
      } catch (e) {
        r.error = e.message;
      }
      r.busy = false;
    },

    async regenerate(row) {
      const ok = await this.$store.ui.confirm({
        title: "Regenerate token for frps@" + row.name + "?",
        message:
          "Every frpc using the current token stops connecting until it is updated. Local client configs sharing this token are rewritten automatically.",
        confirmText: "Regenerate",
        danger: true,
      });
      if (!ok) return;
      try {
        const d = await FRP.api(
          `/api/servers/${encodeURIComponent(row.name)}/token/regenerate?propagate=1`,
          { method: "POST" }
        );
        this.regen = { name: d.name, token: d.token, propagated: d.propagated || [] };
        this.load();
      } catch (e) {
        this.$store.ui.push("regenerate: " + e.message, "bad");
      }
    },

    async remove(row) {
      const ok = await this.$store.ui.confirm({
        title: `Delete frps@${row.name}?`,
        message: "The unit is disabled; the config is kept as a .bak copy beside its old path.",
        confirmText: "Delete",
        danger: true,
      });
      if (!ok) return;
      try {
        const d = await FRP.api(`/api/servers/${encodeURIComponent(row.name)}`, { method: "DELETE" });
        this.$store.ui.push(`deleted ${row.name} (backup: ${d.backup})`, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("delete: " + e.message, "bad");
      }
    },

    async action(unit, act) {
      try {
        await FRP.api(`/api/services/${encodeURIComponent(unit)}/action`, {
          method: "POST",
          body: { action: act },
        });
        this.$store.ui.push(`${act} ${unit} — done`, "ok");
      } catch (e) {
        this.$store.ui.push(`${act} ${unit}: ${e.message}`, "bad");
      }
      this.load();
    },

    async copyTok(text) {
      const ok = await FRP.copy(text);
      this.$store.ui.push(
        ok ? "copied to clipboard" : "copy failed — select the text manually",
        ok ? "ok" : "warn"
      );
    },
  }));

  /* ---- component: clients ---------------------------------------------------- */

  Alpine.data("clientsView", () => ({
    rows: [],
    loading: true,
    localServers: [],

    wiz: null,
    expanded: null,
    addForm: null,
    raw: null,
    edit: null,

    async init() {
      await this.load();
      this.loadLocalServers();
    },

    async load() {
      try {
        const d = await FRP.api("/api/clients");
        this.rows = d.clients || [];
      } catch (e) {
        this.$store.ui.push("cannot list clients: " + e.message, "bad");
      }
      this.loading = false;
    },

    // The token picker reads each local server's TOML — the create API
    // auto-picks when exactly one server exists; the picker makes the
    // multi-server case explicit.
    async loadLocalServers() {
      try {
        const d = await FRP.api("/api/servers");
        const out = [];
        for (const s of d.servers || []) {
          try {
            const det = await FRP.api(`/api/servers/${encodeURIComponent(s.name)}`);
            out.push({
              name: s.name,
              bindAddr: (det.config && det.config.bindAddr) || "",
              bindPort: (det.config && det.config.bindPort) || 0,
              token: det.token || "",
            });
          } catch {
            /* unreadable server — skip */
          }
        }
        this.localServers = out;
      } catch {
        this.localServers = [];
      }
    },

    openCreate() {
      const first = this.localServers[0];
      this.wiz = {
        name: first ? "client-" + first.bindPort : "client-7000",
        serverAddr: first ? first.bindAddr : "10.100.111.2",
        serverPort: first ? first.bindPort : 7000,
        tokenSource: first ? "local:" + first.name : "paste",
        token: first ? first.token : "",
        protocol: "tcp",
        useTls: false,
        useEncryption: false,
        useCompression: false,
        rawSpeed: true,
        tcpMux: false,
        proto: "both",
        ports: "8989,8443,2053",
        localIp: "127.0.0.1",
        webEnabled: true,
        busy: false,
        error: "",
      };
    },

    applyRawSpeed(target) {
      const v = target === "wiz" ? this.wiz : this.edit;
      if (!v) return;
      if (v.rawSpeed) {
        v.useEncryption = false;
        v.useCompression = false;
        v.tcpMux = false;
      } else {
        v.useEncryption = true;
      }
    },

    tokenSources() {
      return [
        ...this.localServers.map((s) => ({
          v: "local:" + s.name,
          label: `local ${s.name} (${s.token ? s.token.slice(0, 6) + "…" : "no token"})`,
        })),
        { v: "paste", label: "paste token manually" },
      ];
    },

    pickToken(source) {
      if (source && source.startsWith("local:")) {
        const srv = this.localServers.find((s) => "local:" + s.name === source);
        if (srv) this.wiz.token = srv.token;
      }
    },

    async create() {
      const w = this.wiz;
      if (!w) return;
      w.busy = true;
      w.error = "";
      try {
        const resp = await FRP.api("/api/clients", {
          method: "POST",
          body: {
            name: w.name.trim() || undefined,
            serverAddr: w.serverAddr.trim(),
            serverPort: Number(w.serverPort),
            token: w.token.trim(),
            protocol: w.protocol,
            useTls: w.useTls,
            useEncryption: w.useEncryption,
            useCompression: w.useCompression,
            tcpMux: w.tcpMux,
            proto: w.proto,
            ports: w.ports.trim(),
            localIp: w.localIp.trim(),
            webEnabled: w.webEnabled,
          },
        });
        this.wiz = null;
        this.$store.ui.push(
          `frpc@${resp.name} — ${resp.proxies} proxies created` +
            (resp.unit_error ? "; unit start failed: " + resp.unit_error : ""),
          resp.unit_error ? "warn" : "ok"
        );
        this.load();
      } catch (e) {
        w.error = e.message;
        w.busy = false;
      }
    },

    toggleExpand(name) {
      this.expanded = this.expanded === name ? null : name;
      this.addForm = null;
    },

    openAdd(name) {
      const row = this.rows.find((r) => r.name === name);
      this.addForm = {
        name,
        ports: "",
        proto: "both",
        localIp: row && row.proxies && row.proxies.length ? row.proxies[0].localIp : "127.0.0.1",
        busy: false,
        error: "",
      };
    },

    async addProxies() {
      const f = this.addForm;
      if (!f) return;
      f.busy = true;
      f.error = "";
      try {
        const d = await FRP.api(`/api/clients/${encodeURIComponent(f.name)}/proxies`, {
          method: "POST",
          body: { ports: f.ports.trim(), proto: f.proto, localIp: f.localIp.trim() },
        });
        this.$store.ui.push(`added ${d.added} proxies (${d.total} total)`, "ok");
        this.addForm = null;
        this.load();
      } catch (e) {
        f.error = e.message;
        f.busy = false;
      }
    },

    async removeProxy(row, proxy) {
      const ok = await this.$store.ui.confirm({
        title: `Remove proxy ${proxy.name}?`,
        message: "Deletes the port rule from " + row.name + " and restarts the unit if it is active.",
        confirmText: "Remove",
        danger: true,
      });
      if (!ok) return;
      try {
        const d = await FRP.api(
          `/api/clients/${encodeURIComponent(row.name)}/proxies?ports=${proxy.remotePort}`,
          { method: "DELETE" }
        );
        this.$store.ui.push(`removed ${d.removed.join(", ")}`, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("remove: " + e.message, "bad");
      }
    },

    async openEdit(row) {
      try {
        if ((row.style || "managed") !== "managed") {
          await this.openRaw(row.name);
          return;
        }
        const d = await FRP.api(`/api/clients/${encodeURIComponent(row.name)}`);
        const c = d.config || {};
        const style = d.style || c.style || row.style || "managed";
        if (style !== "managed") {
          await this.openRaw(row.name);
          return;
        }
        const proxies = c.proxies || row.proxies || [];
        const ports = [...new Set(proxies.map((p) => p.remotePort))].sort((a, b) => a - b);
        const hasTCP = proxies.some((p) => p.type === "tcp");
        const hasUDP = proxies.some((p) => p.type === "udp");
        const first = proxies[0] || {};
        const enc = first.useEncryption === true;
        const tls = c.tls !== undefined ? !!c.tls : false;
        this.edit = {
          name: row.name,
          style,
          serverAddr: c.serverAddr || row.serverAddr,
          serverPort: c.serverPort || row.serverPort,
          token: "",
          protocol: c.protocol || row.protocol || "tcp",
          ports: c.portsSpec || ports.join(","),
          proto: hasTCP && hasUDP ? "both" : hasUDP ? "udp" : "tcp",
          localIp: first.localIp || "127.0.0.1",
          useTls: tls,
          useEncryption: enc,
          useCompression: first.useCompression === true,
          tcpMux: c.tcpMux !== undefined ? !!c.tcpMux : !!row.tcpMux,
          tcpMuxKeepaliveInterval: c.tcpMuxKeepaliveInterval || 10,
          dialServerTimeout: c.dialServerTimeout || 5,
          dialServerKeepalive: c.dialServerKeepalive || 15,
          poolCount: c.poolCount || 40,
          heartbeatInterval: c.heartbeatInterval || 10,
          heartbeatTimeout: c.heartbeatTimeout || 25,
          quicKeepalivePeriod: c.quicKeepalivePeriod || 10,
          quicMaxIdleTimeout: c.quicMaxIdleTimeout || 30,
          quicMaxIncomingStreams: c.quicMaxIncomingStreams || 100000,
          loginFailExit: !!c.loginFailExit,
          rangeTemplate: !!c.rangeTemplate,
          restart: !!(d.unit && d.unit.active === "active"),
          rawSpeed: !enc,
          busy: false,
          error: "",
        };
      } catch (e) {
        this.$store.ui.push(`cannot open ${row.name}: ${e.message}`, "bad");
      }
    },

    async saveEdit() {
      const e = this.edit;
      if (!e) return;
      e.busy = true;
      e.error = "";
      try {
        await FRP.api(`/api/clients/${encodeURIComponent(e.name)}`, {
          method: "PUT",
          body: {
            serverAddr: e.serverAddr.trim(),
            serverPort: Number(e.serverPort),
            protocol: e.protocol,
            useTls: e.useTls,
            useEncryption: e.useEncryption,
            useCompression: e.useCompression,
            tcpMux: e.tcpMux,
            tcpMuxKeepaliveInterval: Number(e.tcpMuxKeepaliveInterval) || 0,
            dialServerTimeout: Number(e.dialServerTimeout) || 5,
            dialServerKeepalive: Number(e.dialServerKeepalive) || 15,
            poolCount: Number(e.poolCount) || 40,
            heartbeatInterval: Number(e.heartbeatInterval) || 10,
            heartbeatTimeout: Number(e.heartbeatTimeout) || 25,
            quicKeepalivePeriod: Number(e.quicKeepalivePeriod) || 10,
            quicMaxIdleTimeout: Number(e.quicMaxIdleTimeout) || 30,
            quicMaxIncomingStreams: Number(e.quicMaxIncomingStreams) || 100000,
            loginFailExit: !!e.loginFailExit,
            restart: !!e.restart,
            ports: e.ports.trim(),
            proto: e.proto,
            localIp: e.localIp.trim(),
            ...(e.token.trim() ? { token: e.token.trim() } : {}),
          },
        });
        this.$store.ui.push("client updated — verify passed, unit restarted if active", "ok");
        this.edit = null;
        this.load();
      } catch (err) {
        if (/raw|TOML/i.test(err.message)) {
          this.edit = null;
          await this.openRaw(e.name);
          this.$store.ui.push(err.message, "warn");
          return;
        }
        e.error = err.message;
        e.busy = false;
      }
    },

    async openRaw(name) {
      try {
        const d = await FRP.api(`/api/clients/${encodeURIComponent(name)}/raw`);
        this.raw = { name, style: d.style, content: d.content, busy: false, error: "", saved: "" };
      } catch (e) {
        this.$store.ui.push(name + ": " + e.message, "bad");
      }
    },

    async saveRaw() {
      const r = this.raw;
      if (!r) return;
      r.busy = true;
      r.error = "";
      try {
        const d = await FRP.api(`/api/clients/${encodeURIComponent(r.name)}/raw`, {
          method: "PUT",
          body: { content: r.content },
        });
        r.saved = `saved — verify: ${d.verify}, backup: ${d.backup || "n/a"}`;
        this.load();
      } catch (e) {
        r.error = e.message;
      }
      r.busy = false;
    },

    async remove(row) {
      const ok = await this.$store.ui.confirm({
        title: `Delete frpc@${row.name}?`,
        message: "The unit is disabled; the config is kept as a .bak copy.",
        confirmText: "Delete",
        danger: true,
      });
      if (!ok) return;
      try {
        const d = await FRP.api(`/api/clients/${encodeURIComponent(row.name)}`, { method: "DELETE" });
        this.$store.ui.push(`deleted ${row.name} (backup: ${d.backup})`, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("delete: " + e.message, "bad");
      }
    },

    async action(unit, act) {
      try {
        await FRP.api(`/api/services/${encodeURIComponent(unit)}/action`, {
          method: "POST",
          body: { action: act },
        });
        this.$store.ui.push(`${act} ${unit} — done`, "ok");
      } catch (e) {
        this.$store.ui.push(`${act} ${unit}: ${e.message}`, "bad");
      }
      this.load();
    },
  }));

  /* ---- component: GRE -------------------------------------------------------- */

  Alpine.data("greView", () => ({
    tunnels: [],
    unreadable: {},
    loading: true,

    form: null,
    test: null,
    mirror: null,

    async init() {
      await this.load();
    },

    async load() {
      try {
        const d = await FRP.api("/api/gre");
        this.tunnels = d.tunnels || [];
        this.unreadable = d.unreadable || {};
      } catch (e) {
        this.$store.ui.push("cannot list tunnels: " + e.message, "bad");
      }
      this.loading = false;
    },

    openCreate() {
      this.form = {
        edit: false,
        name: "gt11",
        localPublicIp: "",
        remotePublicIp: "",
        localPrivateIp: "",
        remotePrivateIp: "",
        mtu: 1280,
        mssMode: "clamp",
        txqueuelen: 1000,
        restart: true,
        busy: false,
        error: "",
      };
    },

    openEdit(t) {
      this.form = {
        edit: true,
        name: t.name,
        iface: t.iface,
        localPublicIp: t.local_public_ip || "",
        remotePublicIp: t.remote_public_ip || "",
        localPrivateIp: t.local_private_ip || "",
        remotePrivateIp: t.remote_private_ip || "",
        mtu: t.mtu || 1280,
        mssMode: t.mss_mode || "clamp",
        txqueuelen: t.txqueuelen || 1000,
        restart: true,
        busy: false,
        error: "",
      };
    },

    async save() {
      const f = this.form;
      if (!f) return;
      f.busy = true;
      f.error = "";
      try {
        const body = {
          localPublicIp: f.localPublicIp.trim(),
          remotePublicIp: f.remotePublicIp.trim(),
          localPrivateIp: f.localPrivateIp.trim(),
          remotePrivateIp: f.remotePrivateIp.trim(),
          mtu: Number(f.mtu),
          mssMode: f.mssMode,
          txqueuelen: Number(f.txqueuelen),
        };
        let resp;
        if (f.edit) {
          body.restart = !!f.restart;
          resp = await FRP.api(`/api/gre/${encodeURIComponent(f.name)}`, {
            method: "PUT",
            body,
          });
        } else {
          body.name = f.name.trim();
          resp = await FRP.api("/api/gre", { method: "POST", body });
        }
        const t = resp.tunnel;
        const notes = [];
        if (resp.warnings && resp.warnings.length) notes.push(resp.warnings.join("; "));
        if (resp.unit_error) notes.push("unit restart failed: " + resp.unit_error);
        if (f.edit && resp.restarted === false && !resp.unit_error && !f.restart)
          notes.push("restart deferred — run `systemctl restart gre-tunnel@" + t.name + "` to apply");
        this.form = null;
        this.$store.ui.push(
          `tunnel ${t.name} ${f.edit ? "updated" : "created"}${
            notes.length ? " — " + notes.join("; ") : ""
          }`,
          resp.unit_error ? "warn" : "ok"
        );
        this.load();
      } catch (e) {
        f.error = e.message;
        f.busy = false;
      }
    },

    async linkTest(t) {
      this.test = { name: t.name, running: true, result: null };
      try {
        this.test.result = await FRP.api(`/api/gre/${encodeURIComponent(t.name)}/test`, {
          method: "POST",
        });
      } catch (e) {
        this.test = { name: t.name, running: false, result: { error: e.message } };
        return;
      }
      this.test.running = false;
    },

    async openMirror(t) {
      try {
        const d = await FRP.api(`/api/gre/${encodeURIComponent(t.name)}/mirror`);
        this.mirror = { name: d.name, env: d.env_file };
      } catch (e) {
        this.$store.ui.push("mirror: " + e.message, "bad");
      }
    },

    async copyMirror() {
      const ok = await FRP.copy(this.mirror.env);
      this.$store.ui.push(ok ? "mirror config copied" : "copy failed", ok ? "ok" : "warn");
    },

    async remove(t) {
      const ok = await this.$store.ui.confirm({
        title: `Delete GRE tunnel ${t.name}?`,
        message:
          "Tears the interface down, removes its iptables rules and deletes the env definition. Run the mirrored delete on the peer node as well.",
        confirmText: "Delete tunnel",
        danger: true,
      });
      if (!ok) return;
      try {
        await FRP.api(`/api/gre/${encodeURIComponent(t.name)}`, { method: "DELETE" });
        this.$store.ui.push(`tunnel ${t.name} removed`, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("delete: " + e.message, "bad");
      }
    },
  }));

  /* ---- component: turbo -------------------------------------------------------- */

  Alpine.data("turboView", () => ({
    state: null,
    busy: false,
    zramSize: 2048,
    zramAlgo: "lz4",
    zramSizes: [512, 1024, 2048, 4096, 8192],
    zramAlgos: ["lz4", "zstd", "lzo", "lzo-rle"],

    async init() {
      await this.load();
      const c = this.zramConfig;
      if (c) {
        this.zramSize = c.SizeMB || 2048;
        this.zramAlgo = c.Algo || "lz4";
      }
    },

    async load() {
      try {
        this.state = await FRP.api("/api/system/turbo");
      } catch (e) {
        this.$store.ui.push("cannot read turbo state: " + e.message, "bad");
      }
    },

    get zramConfig() {
      return this.state && this.state.zram ? this.state.zram.config : null;
    },
    get zramActive() {
      return this.state && this.state.zram ? this.state.zram.active : null;
    },
    get sysctlRows() {
      const sc = (this.state && this.state.sysctl) || {};
      return Object.entries(sc).map(([k, v]) => ({ k, v }));
    },
    get gcCron() {
      return (this.state && this.state.gcCron) || null;
    },

    async gcCronRun() {
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", { method: "POST", body: { action: "gc-cron" } });
        this.$store.ui.push(d.status + (d.output ? " — " + d.output : ""), "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("gc cron: " + e.message, "bad");
      }
      this.busy = false;
    },

    async volatileLogs() {
      const ok = await this.$store.ui.confirm({
        title: "Move logs to volatile memory?",
        message:
          "Disables rsyslog and configures journald with Storage=volatile, SystemMaxUse=50M, SystemKeepFree=5M. Logs will not survive a reboot.",
        confirmText: "Apply",
      });
      if (!ok) return;
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", { method: "POST", body: { action: "volatile-logs" } });
        this.$store.ui.push(d.status, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("volatile logs: " + e.message, "bad");
      }
      this.busy = false;
    },

    async clearLogs() {
      const ok = await this.$store.ui.confirm({
        title: "Permanently clear all system logs?",
        message:
          "Vacuums the journal, truncates /var/log/*.log and wtmp/btmp, and deletes rotated .gz/.1–.9 logs. This cannot be undone.",
        confirmText: "Clear logs",
        danger: true,
      });
      if (!ok) return;
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", { method: "POST", body: { action: "clear-logs" } });
        this.$store.ui.push(d.status, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("clear logs: " + e.message, "bad");
      }
      this.busy = false;
    },

    async apply() {
      const ok = await this.$store.ui.confirm({
        title: "Apply kernel turbo?",
        message:
          "Installs the BBR+fq sysctl drop-in (32 MB socket buffers, somaxconn 65535, ip_forward) and enables tunnel-turbo.service persistently.",
        confirmText: "Apply turbo",
      });
      if (!ok) return;
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", { method: "POST", body: { action: "apply" } });
        this.$store.ui.push("turbo applied — " + d.status, "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("apply: " + e.message, "bad");
      }
      this.busy = false;
    },

    async revert() {
      const ok = await this.$store.ui.confirm({
        title: "Revert turbo?",
        message: "Disables tunnel-turbo and removes the sysctl drop-in. Live values persist until reboot.",
        confirmText: "Revert",
        danger: true,
      });
      if (!ok) return;
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", { method: "POST", body: { action: "revert" } });
        this.$store.ui.push(d.status + (d.unit_error ? " — " + d.unit_error : ""), d.unit_error ? "warn" : "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("revert: " + e.message, "bad");
      }
      this.busy = false;
    },

    async zramOn() {
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", {
          method: "POST",
          body: { action: "zram-on", size: Number(this.zramSize), algo: this.zramAlgo },
        });
        this.$store.ui.push(
          d.status + (d.zram ? ` (${d.zram.SizeMB} MB ${d.zram.Algo})` : ""),
          "ok"
        );
        this.load();
      } catch (e) {
        this.$store.ui.push("zram-on: " + e.message, "bad");
      }
      this.busy = false;
    },

    async zramOff() {
      const ok = await this.$store.ui.confirm({
        title: "Disable ZRAM?",
        message: "Turns off the zram swap device and disables frp-zram.service.",
        confirmText: "Disable ZRAM",
        danger: true,
      });
      if (!ok) return;
      this.busy = true;
      try {
        const d = await FRP.api("/api/system/turbo", { method: "POST", body: { action: "zram-off" } });
        this.$store.ui.push(d.status + (d.unit_error ? " — " + d.unit_error : ""), d.unit_error ? "warn" : "ok");
        this.load();
      } catch (e) {
        this.$store.ui.push("zram-off: " + e.message, "bad");
      }
      this.busy = false;
    },

    fmtBytes(n) {
      return FRP.fmtBytes(n);
    },
  }));

  /* ---- component: logs --------------------------------------------------------- */

  Alpine.data("logsView", () => ({
    units: [],
    unit: "",
    lines: 200,
    lineOpts: [50, 100, 200, 500, 1000],
    started: false,

    async init() {
      try {
        const d = await FRP.api("/api/logs/units");
        this.units = d.units || [];
        if (this.units.length) {
          this.unit = this.units.includes("frp-panel") ? "frp-panel" : this.units[0];
          this.start();
        }
      } catch (e) {
        this.$store.ui.push("cannot list units: " + e.message, "bad");
      }
    },

    get store() {
      return this.$store.logs;
    },

    start() {
      const store = this.$store.logs;
      const el = this.$refs.stream;
      if (!el) return;
      store.paused = false;
      store.follow = true;
      store.reset();
      const url = `/api/logs/stream?unit=${encodeURIComponent(this.unit)}&lines=${this.lines}`;
      FRP.sse.connect(el, url, {
        names: ["open", "eof", "overflow"],
        onEvent: (ev) => store.onEvent(ev.kind, ev.type, ev.data),
      });
      FRP.cleanup(() => FRP.sse.disconnect(el));
      this.started = true;
      this.$nextTick(() => this.scrollEnd());
    },

    stop() {
      FRP.sse.disconnect(this.$refs.stream);
      this.$store.logs.connected = false;
      this.$store.logs.streamNote = "stream stopped";
      this.started = false;
    },

    restart() {
      this.stop();
      this.$nextTick(() => this.start());
    },

    clear() {
      this.$store.logs.reset();
    },

    scrollEnd() {
      const el = this.$refs.pane;
      if (el && this.store.follow) el.scrollTop = el.scrollHeight;
    },
  }));

  /* ---- component: stats ---------------------------------------------------------- */

  Alpine.data("statsView", () => ({
    instances: [],
    history: {},
    selected: "",
    loading: true,
    chart: null,

    async init() {
      await this.load();
      const t = setInterval(() => {
        if (!this.$root.isConnected) {
          clearInterval(t);
          return;
        }
        this.load();
      }, 15000);
      FRP.cleanup(() => {
        clearInterval(t);
        if (this.chart) {
          this.chart.destroy();
          this.chart = null;
        }
      });
    },

    async load() {
      try {
        const d = await FRP.api("/api/stats");
        this.instances = d.instances || [];
        this.history = d.history || {};
        if (!this.selected && this.instances.length) this.selected = this.instances[0].name;
      } catch (e) {
        this.$store.ui.push("cannot read stats: " + e.message, "bad");
      }
      this.loading = false;
      this.$nextTick(() => this.renderChart());
    },

    get cur() {
      return this.instances.find((i) => i.name === this.selected) || null;
    },
    get curHistory() {
      return this.history[this.selected] || [];
    },

    fmtBytes(n) {
      return FRP.fmtBytes(n);
    },

    renderChart() {
      const el = this.$refs.chart;
      if (!el || !FRP.chart.available() || !this.cur) return;
      if (!this.chart) {
        this.chart = FRP.chart.create(el, 210, [
          {},
          { label: "traffic in", stroke: "#22d3ee", fill: "rgba(34,211,238,0.08)" },
          { label: "traffic out", stroke: "#34d399", fill: "rgba(52,211,153,0.08)" },
        ]);
      }
      if (!this.chart) return;
      const h = this.curHistory;
      if (!h.length) {
        this.chart.set([[], [], []]);
        return;
      }
      this.chart.set([
        h.map((s) => Math.floor(Date.parse(s.ts) / 1000)),
        h.map((s) => s.in || 0),
        h.map((s) => s.out || 0),
      ]);
    },
  }));

  /* ---- component: backup ------------------------------------------------------------ */

  Alpine.data("backupView", () => ({
    includeSecrets: false,
    exporting: false,

    categories: [
      { id: "frp", label: "FRP configs", hint: "/root/frp TOMLs + GRE envs", on: true },
      { id: "systemd", label: "systemd units", hint: "the suite's unit files", on: true },
      { id: "turbo", label: "turbo", hint: "sysctl drop-in, bbr.conf, zram.env", on: true },
      { id: "panel", label: "panel", hint: "/etc/frp-panel (panel.toml, watchdog.env)", on: false },
    ],
    restartAfter: true,
    regenerate: true,

    importing: false,
    overDrag: false,
    file: null,
    result: null,
    error: "",

    async doExport() {
      this.exporting = true;
      try {
        const resp = await FRP.api(this.exportUrl(), { raw: true });
        if (!resp.ok) throw new Error("export failed (" + resp.status + ")");
        const blob = await resp.blob();
        const cd = resp.headers.get("Content-Disposition") || "";
        const m = /filename="?([^";]+)"?/.exec(cd);
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = m ? m[1] : "frp-suite-backup.zip";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 8000);
        this.$store.ui.push(
          this.includeSecrets
            ? "backup exported — secrets included, store it safely"
            : "backup exported (secrets redacted)",
          this.includeSecrets ? "warn" : "ok"
        );
      } catch (e) {
        this.$store.ui.push("export: " + e.message, "bad");
      }
      this.exporting = false;
    },

    exportUrl() {
      return "/api/backup/export" + (this.includeSecrets ? "?secrets=1" : "");
    },

    pickFile(ev) {
      const f = ev.target && ev.target.files ? ev.target.files[0] : null;
      if (f) this.setFile(f);
    },
    onDrop(ev) {
      this.overDrag = false;
      const f = ev.dataTransfer && ev.dataTransfer.files ? ev.dataTransfer.files[0] : null;
      if (f) this.setFile(f);
    },
    setFile(f) {
      if (!/\.zip$/i.test(f.name)) {
        this.error = "choose a .zip archive produced by this panel's export";
        return;
      }
      this.error = "";
      this.result = null;
      this.file = f;
    },

    async doImport() {
      if (!this.file) return;
      this.importing = true;
      this.error = "";
      this.result = null;
      const fd = new FormData();
      fd.append("file", this.file);
      for (const c of this.categories) if (c.on) fd.append("categories", c.id);
      if (this.restartAfter) fd.append("restart", "1");
      if (!this.regenerate) fd.append("regenerate", "0");
      try {
        this.result = await FRP.api("/api/backup/import", { method: "POST", form: fd });
        const n = Object.keys((this.result.summary && this.result.summary.restored) || {}).length;
        this.$store.ui.push(`restore done — ${n} files written`, "ok");
      } catch (e) {
        this.error = e.message;
      }
      this.importing = false;
    },

    restoredEntries() {
      if (!this.result || !this.result.summary) return [];
      return Object.entries(this.result.summary.restored || {}).map(([entry, path]) => ({
        entry,
        path,
      }));
    },
  }));

  /* ---- component: watchdog -------------------------------------------------------------- */

  Alpine.data("watchdogView", () => ({
    state: null,
    form: null,
    busy: false,
    tgBusy: false,

    async init() {
      await this.load();
    },

    async load() {
      try {
        this.state = await FRP.api("/api/watchdog");
        const c = this.state.config;
        const active = this.state.unit && this.state.unit.active === "active";
        this.form = {
          enabled: !!active,
          interval: c ? c.interval : 15,
          threshold: c ? c.threshold : 3,
          cooldown: c ? c.cooldown : 60,
          pingTimeout: c ? c.ping_timeout : 2,
          tcpTimeout: c ? c.tcp_timeout : 3,
          // Never pre-fill the secret: the GET value is already masked and
          // the input stays blank ("keep current") unless the user types.
          tgBotToken: "",
          tgTokenMasked: c && c.tg_bot_token ? c.tg_bot_token : "",
          tgChatId: c ? c.tg_chat_id : "",
          tgApiBase: c && c.tg_api_base ? c.tg_api_base : "https://api.telegram.org",
          clearTelegram: false,
        };
      } catch (e) {
        this.$store.ui.push("cannot read watchdog state: " + e.message, "bad");
      }
    },

    get events() {
      return this.state && this.state.events ? this.state.events : [];
    },

    get telegramEnabled() {
      return !!(this.state && this.state.telegram_enabled);
    },

    async save() {
      const f = this.form;
      if (!f) return;
      this.busy = true;
      try {
        const body = { enabled: !!f.enabled };
        ["interval", "threshold", "cooldown", "pingTimeout", "tcpTimeout"].forEach((k) => {
          const v = parseInt(f[k], 10);
          if (!isNaN(v)) body[k] = v;
        });
        body.tgChatId = (f.tgChatId || "").trim();
        body.tgApiBase = (f.tgApiBase || "").trim();
        if (f.tgBotToken && f.tgBotToken.trim()) body.tgBotToken = f.tgBotToken.trim();
        if (f.clearTelegram) body.clearTelegram = true;
        const d = await FRP.api("/api/watchdog", { method: "POST", body });
        this.$store.ui.push(
          `watchdog ${d.status}` + (d.unit_error ? " — unit error: " + d.unit_error : ""),
          d.unit_error ? "warn" : "ok"
        );
        this.load();
      } catch (e) {
        this.$store.ui.push("save: " + e.message, "bad");
      }
      this.busy = false;
    },

    async testTelegram() {
      const f = this.form;
      if (!f) return;
      this.tgBusy = true;
      try {
        const body = {};
        if (f.tgBotToken && f.tgBotToken.trim()) body.tgBotToken = f.tgBotToken.trim();
        if ((f.tgChatId || "").trim()) body.tgChatId = f.tgChatId.trim();
        if ((f.tgApiBase || "").trim()) body.tgApiBase = f.tgApiBase.trim();
        const d = await FRP.api("/api/watchdog/test-telegram", { method: "POST", body });
        this.$store.ui.push("Telegram test alert sent to " + (d.chat_id || "chat"), "ok");
      } catch (e) {
        this.$store.ui.push("telegram test: " + e.message, "bad");
      }
      this.tgBusy = false;
    },
  }));

  /* ---- component: login page ----------------------------------------------------------- */

  Alpine.data("loginPage", () => ({
    step: "checking", // checking | form | change
    username: "admin",
    password: "",
    error: "",
    lockLeft: 0,
    busy: false,
    shakeOn: false,
    newPassword: "",
    confirm2: "",
    changeError: "",

    async init() {
      try {
        const me = await FRP.api("/api/auth/me");
        if (me.must_change_password) {
          this.step = "change";
        } else {
          location.href = "/";
        }
        return;
      } catch {
        this.step = "form";
      }
    },

    async login() {
      this.busy = true;
      this.error = "";
      try {
        const d = await FRP.api("/api/auth/login", {
          method: "POST",
          body: { username: this.username.trim(), password: this.password },
        });
        if (d.must_change_password) {
          this.step = "change";
        } else {
          location.href = "/";
        }
        return;
      } catch (e) {
        this.error = e.message;
        if (e.status === 429 && e.data && e.data.retry_after) {
          this.startLockout(e.data.retry_after);
        } else {
          this.shakeOn = true;
          setTimeout(() => (this.shakeOn = false), 480);
        }
      }
      this.busy = false;
    },

    startLockout(seconds) {
      this.lockLeft = seconds;
      const t = setInterval(() => {
        this.lockLeft--;
        if (this.lockLeft <= 0) clearInterval(t);
      }, 1000);
    },

    async changePassword() {
      this.changeError = "";
      if (this.newPassword.length < 10) {
        this.changeError = "new password must be at least 10 characters";
        return;
      }
      if (this.newPassword !== this.confirm2) {
        this.changeError = "passwords do not match";
        return;
      }
      this.busy = true;
      try {
        await FRP.api("/api/auth/password", {
          method: "POST",
          body: { current_password: this.password, new_password: this.newPassword },
        });
        location.href = "/";
      } catch (e) {
        this.changeError = e.message;
        this.busy = false;
      }
    },
  }));
});
