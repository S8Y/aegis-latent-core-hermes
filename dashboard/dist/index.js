/**
 * aegis-latent — Hermes Dashboard Threat Lab Tab
 *
 * Single IIFE bundle — no build step required.
 * Uses window.__HERMES_PLUGIN_SDK__  for React, hooks, components, fetchJSON.
 * Falls back to   window.__HERMES_PLUGINS__   for older dashboard builds.
 * Registers via    window.__HERMES_PLUGINS__.register(name, component).
 *
 * Backend routes: /api/plugins/aegis-latent/{stats,alerts,engines,full,scan}
 */
(function boot() {
  "use strict";

  /* ── Resolve SDK ────────────────────────────────────────────────────
   * __HERMES_PLUGIN_SDK__  is canonical (v2.4+ dashboard).
   * __HERMES_PLUGINS__     older dashboard that put everything on one object.
   * We try both so the same bundle works on any Hermes version.        */
  var SDK = window.__HERMES_PLUGIN_SDK__ || window.__HERMES_PLUGINS__;
  var REG = window.__HERMES_PLUGINS__    || window.__HERMES_PLUGIN_SDK__;

  if (!SDK || !SDK.React || typeof SDK.React.createElement !== "function") {
    setTimeout(boot, 50);
    return;
  }

  /* ── SDK imports ─────────────────────────────────────────────────── */
  var React       = SDK.React;
  var h           = React.createElement;
  var useState    = SDK.hooks.useState;
  var useEffect   = SDK.hooks.useEffect;
  var useCallback = SDK.hooks.useCallback;
  var useRef      = SDK.hooks.useRef;

  var Card        = SDK.components.Card;
  var CardHeader  = SDK.components.CardHeader;
  var CardTitle   = SDK.components.CardTitle;
  var CardContent = SDK.components.CardContent;
  var Badge       = SDK.components.Badge;
  var Button      = SDK.components.Button;

  var api = SDK.fetchJSON;
  var cn  = (SDK.utils && SDK.utils.cn) || function (c) { return c; };

  var BASE    = "/api/plugins/aegis-latent";
  var POLL_MS = 5000;

  /* ── Utilities ───────────────────────────────────────────────────── */
  function timeAgo(isoStr) {
    if (!isoStr) return "";
    var diff = Date.now() - new Date(isoStr).getTime();
    if (isNaN(diff)) return "";
    var s = Math.floor(diff / 1000);
    if (s < 5)   return "just now";
    if (s < 60)  return s + "s ago";
    var m = Math.floor(s / 60);
    if (m < 60)  return m + "m ago";
    return Math.floor(m / 60) + "h ago";
  }

  function shorten(t, n) {
    if (!t) return "";
    return t.length <= n ? t : t.slice(0, n) + "\u2026";
  }

  function sevColor(sev) {
    return ({
      critical: "var(--color-destructive, #ef4444)",
      high:     "#f97316",
      medium:   "var(--color-warning, #f59e0b)",
      low:      "#3b82f6",
      clean:    "var(--color-success, #22c55e)"
    })[sev] || "var(--color-success, #22c55e)";
  }

  function throttle(fn, ms) {
    var last = 0;
    return function () {
      var now = Date.now();
      if (now - last >= ms) { last = now; return fn.apply(this, arguments); }
    };
  }

  /* ── Sub-components ──────────────────────────────────────────────── */

  /* Stat card (overview row) */
  function StatCard(props) {
    return h(Card, { className:
        "aegis-stat-card" +
        (props.danger  ? " aegis-danger" : "") +
        (props.warning ? " aegis-warning" : "") +
        (props.success ? " aegis-success" : "")
      },
      h("div", { className: "aegis-stat-value" },
        typeof props.value === "number" ? props.value.toLocaleString() : props.value
      ),
      h("div", { className: "aegis-stat-label" }, props.label)
    );
  }

  /* Severity bar chart */
  function SeverityBars(props) {
    var names   = ["critical", "high", "medium", "low", "clean"];
    var counts  = props.counts || {};
    var maxVal  = 1;
    names.forEach(function (s) { if ((counts[s] || 0) > maxVal) maxVal = counts[s]; });

    return h("div", { className: "aegis-bars" },
      names.map(function (sev) {
        var c    = counts[sev] || 0;
        var pct  = maxVal > 0 ? (c / maxVal) * 100 : 0;
        return h("div", { key: sev, className: cn("aegis-bar", "aegis-bar-" + sev),
            style: { height: Math.max(pct, 4) + "%" }, title: sev + ": " + c
          },
          h("span", { className: "aegis-bar-count" }, c > 0 ? c.toLocaleString() : ""),
          h("span", { className: "aegis-bar-label" }, sev === "critical" ? "crit" : sev)
        );
      })
    );
  }

  /* Engine hit-rate row */
  function EngineRow(props) {
    var pct = Math.min((props.count / (props.maxVal || 1)) * 100, 100);
    return h("tr", null,
      h("td", { className: "aegis-cell-name" }, props.name),
      h("td", { className: "aegis-cell-count" }, props.count.toLocaleString()),
      h("td", null,
        h("div", { className: "aegis-engine-bar-bg" },
          h("div", { className: "aegis-engine-bar-fill",
            style: { width: pct + "%", background: "var(--color-ring, #3b82f6)" }
          })
        )
      )
    );
  }

  /* Single alert item */
  function AlertItem(props) {
    var a   = props.alert;
    var cls = "aegis-alert-item";
    if (a.severity === "critical") cls += " aegis-alert-critical";
    else if (a.severity === "high") cls += " aegis-alert-high";

    return h("div", { className: cls },
      h("div", { className: "aegis-alert-meta" },
        h("span", { className: "aegis-alert-severity aegis-alert-severity-" + a.severity,
            style: { color: sevColor(a.severity) } }, a.severity),
        h("span", { className: "aegis-alert-time" }, timeAgo(a.timestamp)),
        h(Badge, { variant: a.verdict === "block" ? "destructive" : "secondary" }, a.verdict)
      ),
      h("div", { className: "aegis-alert-text" }, shorten(a.text_snippet, 120)),
      a.flagged_engines && a.flagged_engines.length
        ? h("div", { className: "aegis-alert-engines" },
            a.flagged_engines.map(function (e) {
              return h("span", { key: e, className: "aegis-badge aegis-badge-flag",
                style: { fontSize: "0.6rem" } }, shorten(e, 30));
            })
          )
        : null
    );
  }

  /* On-demand scan result table */
  function ScanResultDisplay(props) {
    var r = props.result;
    if (!r) return null;

    var verdictClass = "aegis-badge" + (
      r.overall_verdict === "block" ? " aegis-badge-block"
      : r.overall_verdict !== "clean" ? " aegis-badge-flag"
      : " aegis-badge-clean"
    );

    return h(Card, { className: "aegis-scan-card" },
      h(CardContent, { className: "aegis-scan-result" },
        h("div", { className: "aegis-scan-summary" },
          h("span", { className: verdictClass }, r.overall_verdict),
          h("span", null,
            "Severity: ", h("strong", { style: { color: sevColor(r.max_severity) } }, r.max_severity),
            "  |  Score: ", r.max_score.toFixed(3),
            "  |  ", r.engines_flagged, "/", r.total_engines, " engines"
          ),
          h("span", { className: "aegis-scan-duration" }, r.duration_ms.toFixed(1), "ms")
        ),
        r.results && r.results.length
          ? h("table", { className: "aegis-engine-table" },
              h("thead", null, h("tr", null,
                h("th", null, "Engine"), h("th", null, "Category"),
                h("th", null, "Score"), h("th", null, "Severity"), h("th", null, "Status")
              )),
              h("tbody", null,
                r.results.map(function (er) {
                  return h("tr", { key: er.engine },
                    h("td", null, shorten(er.engine, 28)),
                    h("td", null, h("code", null, er.category)),
                    h("td", null, er.score.toFixed(3)),
                    h("td", null, h("span", {
                      style: { color: sevColor(er.severity), fontWeight: 600 }
                    }, er.severity)),
                    h("td", null,
                      er.flagged
                        ? h(Badge, { variant: "destructive" }, "FLAGGED")
                        : h(Badge, { variant: "secondary" }, "clean")
                    )
                  );
                })
              )
            )
          : null
      )
    );
  }

  /* ── Main tab component ──────────────────────────────────────────── */
  function AegisThreatLab() {
    /* state */
    var sStats   = useState(null),  stats      = sStats[0],   setStats      = sStats[1];
    var sAlerts  = useState([]),    alerts     = sAlerts[0],  setAlerts     = sAlerts[1];
    var sEngines = useState(null),  engines    = sEngines[0], setEngines    = sEngines[1];
    var sLoad    = useState(true),  loading    = sLoad[0],    setLoading    = sLoad[1];
    var sError   = useState(null),  error      = sError[0],   setError      = sError[1];
    var sText    = useState(""),    scanText   = sText[0],    setScanText   = sText[1];
    var sResult  = useState(null),  scanResult = sResult[0],  setScanResult = sResult[1];
    var sBusy    = useState(false), scanning   = sBusy[0],    setScanning   = sBusy[1];
    var pollRef  = useRef(null);

    /* ── fetch dashboard data ──────────────────────────────────── */
    var fetchAll = useCallback(function () {
      Promise.all([
        api(BASE + "/stats"),
        api(BASE + "/alerts?limit=50"),
        api(BASE + "/engines")
      ]).then(function (r) {
        setStats(r[0]);
        setAlerts(r[1] ? r[1].alerts || [] : []);
        setEngines(r[2]);
        setLoading(false);
        setError(null);
      }).catch(function (err) {
        setLoading(false);
        setError("Failed to connect to Aegis API: " + (err.message || err));
      });
    }, []);

    var throttledFetch = useCallback(throttle(fetchAll, 1000), [fetchAll]);

    useEffect(function () {
      fetchAll();
      pollRef.current = setInterval(fetchAll, POLL_MS);
      return function () { if (pollRef.current) clearInterval(pollRef.current); };
    }, [fetchAll]);

    /* ── on-demand scan ────────────────────────────────────────── */
    var doScan = useCallback(function () {
      var txt = scanText;
      if (!txt || txt.trim().length < 3) return;
      setScanning(true);
      api(BASE + "/scan", { method: "POST", body: JSON.stringify({ text: txt }) })
        .then(function (res) {
          setScanResult(res);
          setScanning(false);
          throttledFetch();
        })
        .catch(function (err) {
          setScanning(false);
          setError("Scan failed: " + (err.message || err));
        });
    }, [scanText, throttledFetch]);

    var handleKey = useCallback(function (e) {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) doScan();
    }, [doScan]);

    /* ── render ────────────────────────────────────────────────── */
    if (loading) {
      return h(Card, null,
        h(CardContent, { className: "aegis-empty" }, "Loading Aegis Threat Lab\u2026")
      );
    }

    if (error) {
      return h(Card, null,
        h(CardHeader, null, h(CardTitle, null, "Aegis Threat Lab")),
        h(CardContent, null,
          h("div", { className: "aegis-empty", style: { color: "var(--color-destructive)" } },
            "\u26A0 " + error
          ),
          h("div", { style: { textAlign: "center", marginTop: "1rem" } },
            h(Button, { onClick: fetchAll }, "Retry")
          )
        )
      );
    }

    var s          = stats || {};
    var sevCounts  = s.severity_counts || {};
    var engineHits = (engines && engines.engine_hit_counts) || {};
    var catHits    = (engines && engines.category_counts) || {};

    var eMax = 1;
    Object.keys(engineHits).forEach(function (k) { if (engineHits[k] > eMax) eMax = engineHits[k]; });
    var cMax = 1;
    Object.keys(catHits).forEach(function (k) { if (catHits[k] > cMax) cMax = catHits[k]; });

    return h("div", null,

      /* ── header bar ──────────────────────────────────────────── */
      h("div", { className: "aegis-header-bar" },
        h("div", { className: "aegis-header-left" },
          h("h3", { className: "aegis-header-title" }, "Aegis Threat Lab"),
          h("span", { className: "aegis-version" }, "v" + (s.version || "\u2014"))
        ),
        h("div", { className: "aegis-header-right" },
          h("span", { className: "aegis-live-label" }, "live"),
          h("span", { className: "aegis-live-dot" })
        )
      ),

      /* ── scan input ──────────────────────────────────────────── */
      h("div", { className: "aegis-scan-area" },
        h("textarea", { className: "aegis-scan-input",
          value: scanText,
          placeholder: "Paste text to scan for threats\u2026",
          onChange: function (e) { setScanText(e.target.value); },
          onKeyDown: handleKey
        }),
        h(Button, { className: "aegis-scan-btn",
          onClick: doScan,
          disabled: scanning || !scanText || scanText.trim().length < 3,
          variant: "default", size: "sm"
        }, scanning ? "Scanning\u2026" : "Scan")
      ),

      scanResult ? h(ScanResultDisplay, { result: scanResult }) : null,

      /* ── stat cards ──────────────────────────────────────────── */
      h("div", { className: "aegis-grid" },
        h(StatCard, { value: s.scans_total || 0,   label: "Total scans" }),
        h(StatCard, { value: s.scans_clean || 0,   label: "Clean",    success: true }),
        h(StatCard, { value: s.scans_flagged || 0, label: "Flagged",  warning: true }),
        h(StatCard, { value: s.scans_blocked || 0, label: "Blocked",  danger: true }),
        h(StatCard, { value: (s.avg_duration_ms || 0).toFixed(1) + "ms", label: "Avg duration" })
      ),

      /* ── severity distribution ───────────────────────────────── */
      h(Card, null, h(CardContent, null,
        h("div", { className: "aegis-section-title" }, "Severity Distribution"),
        h(SeverityBars, { counts: sevCounts })
      )),

      /* ── engine hits + categories (side-by-side) ─────────────── */
      h("div", { className: "aegis-row" },
        h(Card, null, h(CardContent, null,
          h("div", { className: "aegis-section-title" }, "Engine Hit Rates"),
          Object.keys(engineHits).length === 0
            ? h("div", { className: "aegis-empty" }, "No flagged engines yet")
            : h("table", { className: "aegis-engine-table" },
                h("thead", null, h("tr", null,
                  h("th", null, "Engine"), h("th", null, "Hits"), h("th", null, "")
                )),
                h("tbody", null,
                  Object.keys(engineHits)
                    .sort(function (a, b) { return engineHits[b] - engineHits[a]; })
                    .slice(0, 12)
                    .map(function (name) {
                      return h(EngineRow, {
                        key: name, name: shorten(name, 32),
                        count: engineHits[name], maxVal: eMax
                      });
                    })
                )
              )
        )),
        h(Card, null, h(CardContent, null,
          h("div", { className: "aegis-section-title" }, "Threat Categories"),
          Object.keys(catHits).length === 0
            ? h("div", { className: "aegis-empty" }, "No threats detected yet")
            : h("table", { className: "aegis-engine-table" },
                h("thead", null, h("tr", null,
                  h("th", null, "Category"), h("th", null, "Count"), h("th", null, "")
                )),
                h("tbody", null,
                  Object.keys(catHits)
                    .sort(function (a, b) { return catHits[b] - catHits[a]; })
                    .map(function (name) {
                      return h(EngineRow, {
                        key: name, name: name,
                        count: catHits[name], maxVal: cMax
                      });
                    })
                )
              )
        ))
      ),

      /* ── recent alerts ───────────────────────────────────────── */
      h(Card, null,
        h(CardHeader, null, h(CardTitle, { style: { margin: 0, fontSize: "1rem" } },
          "Recent Alerts ",
          h("span", { className: "aegis-alert-count" },
            "(" + (alerts.length || 0) + ")"
          )
        )),
        h(CardContent, null,
          alerts.length === 0
            ? h("div", { className: "aegis-empty" }, "No alerts \u2014 all clear.")
            : h("div", { className: "aegis-alerts" },
                alerts.slice(0, 30).map(function (a, i) {
                  return h(AlertItem, { key: a.timestamp || i, alert: a });
                })
              )
        )
      )

    );
  }

  /* ── Register tab ────────────────────────────────────────────────── */
  if (REG && typeof REG.register === "function") {
    REG.register("aegis-latent", AegisThreatLab);
  } else {
    /* REG not ready yet — defer */
    setTimeout(boot, 50);
  }
})();
