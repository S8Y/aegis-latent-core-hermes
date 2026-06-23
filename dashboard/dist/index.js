/**
 * aegis-latent — Hermes Dashboard Threat Lab Tab
 *
 * Single IIFE bundle — no build step required.
 * Uses window.__HERMES_PLUGINS__ SDK (or window.React fallback).
 *
 * Routes: /api/plugins/aegis-latent/stats
 *         /api/plugins/aegis-latent/alerts
 *         /api/plugins/aegis-latent/engines
 *         /api/plugins/aegis-latent/full
 *         /api/plugins/aegis-latent/scan (POST)
 */
(function () {
  "use strict";

  function init() {
    var P = window.__HERMES_PLUGINS__;

    // Resolve React — SDK may or may not expose it, fall back to global
    var React = (P && P.React) || window.React;
    if (!React || typeof React.createElement !== "function") {
      // SDK or React not ready yet; retry
      setTimeout(init, 100);
      return;
    }

    var h = React.createElement;
    var useState = React.useState;
    var useEffect = React.useEffect;
    var useCallback = React.useCallback;
    var useRef = React.useRef;

    // SDK components — available only when P is live
    var Card = function () { return null; };
    var CardHeader = function () { return null; };
    var CardTitle = function () { return null; };
    var CardContent = function () { return null; };
    var Badge = function () { return null; };
    var Button = function () { return null; };
    var api = function () { return Promise.resolve(null); };
    var cn = function () { return ""; };

    if (P) {
      if (P.components) {
        Card = P.components.Card || Card;
        CardHeader = P.components.CardHeader || CardHeader;
        CardTitle = P.components.CardTitle || CardTitle;
        CardContent = P.components.CardContent || CardContent;
        Badge = P.components.Badge || Badge;
        Button = P.components.Button || Button;
      }
      api = P.fetchJSON || api;
      cn = (P.utils && P.utils.cn) || cn;
    }

    var BASE = "/api/plugins/aegis-latent";
    var POLL_MS = 5000;

    // ── Helpers ──────────────────────────────────────────────────────────────

    function timeAgo(isoStr) {
      if (!isoStr) return "";
      var ts = new Date(isoStr).getTime();
      if (isNaN(ts)) return "";
      var diff = Date.now() - ts;
      var sec = Math.floor(diff / 1000);
      if (sec < 5) return "just now";
      if (sec < 60) return sec + "s ago";
      var min = Math.floor(sec / 60);
      if (min < 60) return min + "m ago";
      var hrs = Math.floor(min / 60);
      if (hrs < 24) return hrs + "h ago";
      return Math.floor(hrs / 24) + "d ago";
    }

    function shorten(text, maxLen) {
      if (!text) return "";
      if (text.length <= maxLen) return text;
      return text.slice(0, maxLen) + "\u2026";
    }

    function sevColor(sev) {
      var m = { critical: "var(--color-destructive, #ef4444)", high: "#f97316", medium: "var(--color-warning, #f59e0b)", low: "#3b82f6", clean: "var(--color-success, #22c55e)" };
      return m[sev] || m.clean;
    }

    function sevClass(sev) {
      return "aegis-bar-" + (sev || "clean");
    }

    // ── Stat card component ──────────────────────────────────────────────────

    function StatCard(props) {
      return h(Card, { className: "aegis-stat-card" + (props.danger ? " aegis-danger" : "") + (props.warning ? " aegis-warning" : "") + (props.success ? " aegis-success" : "") },
        h("div", { className: "aegis-stat-value" }, typeof props.value === "number" ? props.value.toLocaleString() : props.value),
        h("div", { className: "aegis-stat-label" }, props.label)
      );
    }

    // ── Bar chart component ─────────────────────────────────────────────────

    function SeverityBars(props) {
      var sevs = ["critical", "high", "medium", "low", "clean"];
      var counts = props.counts || {};
      var maxVal = 1;
      sevs.forEach(function (s) { if ((counts[s] || 0) > maxVal) maxVal = counts[s]; });

      return h("div", { className: "aegis-bars" },
        sevs.map(function (sev) {
          var c = counts[sev] || 0;
          var pct = (c / maxVal) * 100;
          return h("div", {
            key: sev,
            className: cn("aegis-bar", sevClass(sev)),
            style: { height: Math.max(pct, 4) + "%" },
            title: sev + ": " + c
          },
            h("span", { className: "aegis-bar-count" }, c > 0 ? c : ""),
            h("span", { className: "aegis-bar-label" }, sev === "critical" ? "crit" : sev)
          );
        })
      );
    }

    // ── Engine hit table row ─────────────────────────────────────────────────

    function EngineRow(props) {
      var maxVal = props.maxVal || 1;
      var pct = Math.min((props.count / maxVal) * 100, 100);
      return h("tr", null,
        h("td", null, props.name),
        h("td", null, props.count),
        h("td", null,
          h("div", { className: "aegis-engine-bar-bg", style: { width: "120px" } },
            h("div", {
              className: "aegis-engine-bar-fill",
              style: { width: pct + "%", background: "var(--color-ring, #3b82f6)" }
            })
          )
        )
      );
    }

    // ── Alert item ──────────────────────────────────────────────────────────

    function AlertItem(props) {
      var a = props.alert;
      var cls = "aegis-alert-item";
      if (a.severity === "critical") cls += " aegis-alert-critical";
      else if (a.severity === "high") cls += " aegis-alert-high";
      return h("div", { className: cls },
        h("div", { className: "aegis-alert-meta" },
          h("span", { className: "aegis-alert-severity aegis-alert-severity-" + a.severity,
                       style: { color: sevColor(a.severity) } }, a.severity),
          h("span", { style: { fontSize: "0.7rem", color: "var(--color-muted-foreground)" } },
            timeAgo(a.timestamp)),
          h(Badge, { variant: a.verdict === "block" ? "destructive" : "secondary" }, a.verdict)
        ),
        h("div", { className: "aegis-alert-text" }, shorten(a.text_snippet, 120)),
        a.flagged_engines && a.flagged_engines.length
          ? h("div", { className: "aegis-alert-engines" },
              a.flagged_engines.map(function (e) {
                return h("span", {
                  key: e,
                  className: "aegis-badge aegis-badge-flag",
                  style: { fontSize: "0.6rem" }
                }, shorten(e, 30));
              })
            )
          : null
      );
    }

    // ── Scan result display ─────────────────────────────────────────────────

    function ScanResultDisplay(props) {
      var r = props.result;
      if (!r) return null;
      var verdictBadge = r.overall_verdict === "block" ? " aegis-badge-block"
                        : r.overall_verdict !== "clean" ? " aegis-badge-flag"
                        : " aegis-badge-clean";
      return h(Card, null,
        h(CardContent, { className: "aegis-scan-result", style: { padding: "0.75rem" } },
          h("div", { style: { display: "flex", gap: "0.75rem", alignItems: "center", marginBottom: "0.5rem" } },
            h("span", { className: "aegis-badge" + verdictBadge }, r.overall_verdict),
            h("span", { style: { fontSize: "0.75rem", color: "var(--color-muted-foreground)" } },
              "Severity: ", h("strong", { style: { color: sevColor(r.max_severity) } }, r.max_severity),
              "  |  Score: ", r.max_score.toFixed(3),
              "  |  ", r.engines_flagged, "/", r.total_engines, " engines flagged",
              "  |  ", r.duration_ms.toFixed(1), "ms"
            )
          ),
          r.results && r.results.length
            ? h("table", { className: "aegis-engine-table" },
                h("thead", null,
                  h("tr", null,
                    h("th", null, "Engine"),
                    h("th", null, "Category"),
                    h("th", null, "Score"),
                    h("th", null, "Severity"),
                    h("th", null, "Status")
                  )
                ),
                h("tbody", null,
                  r.results.map(function (er) {
                    return h("tr", { key: er.engine },
                      h("td", { style: { fontSize: "0.75rem" } }, shorten(er.engine, 28)),
                      h("td", null, h("code", { style: { fontSize: "0.7rem" } }, er.category)),
                      h("td", null, er.score.toFixed(3)),
                      h("td", null,
                        h("span", { style: { color: sevColor(er.severity), fontWeight: 600 } }, er.severity)
                      ),
                      h("td", null,
                        er.flagged
                          ? h(Badge, { variant: "destructive", style: { fontSize: "0.65rem" } }, "FLAGGED")
                          : h(Badge, { variant: "secondary", style: { fontSize: "0.65rem" } }, "clean")
                      )
                    );
                  })
                )
              )
            : null
        )
      );
    }

    // ── Throttle helper ─────────────────────────────────────────────────────

    function throttle(fn, ms) {
      var last = 0;
      return function () {
        var now = Date.now();
        if (now - last >= ms) {
          last = now;
          return fn.apply(this, arguments);
        }
      };
    }

    // ── Main app component ──────────────────────────────────────────────────

    function AegisThreatLab() {
      // State
      var _stats = useState(null), stats = _stats[0], setStats = _stats[1];
      var _alerts = useState([]), alerts = _alerts[0], setAlerts = _alerts[1];
      var _engines = useState(null), engines = _engines[0], setEngines = _engines[1];
      var _loading = useState(true), loading = _loading[0], setLoading = _loading[1];
      var _error = useState(null), error = _error[0], setError = _error[1];
      var _scanText = useState(""), scanText = _scanText[0], setScanText = _scanText[1];
      var _scanResult = useState(null), scanResult = _scanResult[0], setScanResult = _scanResult[1];
      var _scanning = useState(false), scanning = _scanning[0], setScanning = _scanning[1];
      var pollRef = useRef(null);

      // Fetch all data
      var fetchAll = useCallback(function () {
        Promise.all([
          api(BASE + "/stats"),
          api(BASE + "/alerts?limit=50"),
          api(BASE + "/engines")
        ]).then(function (results) {
          setStats(results[0]);
          setAlerts(results[1] ? results[1].alerts || [] : []);
          setEngines(results[2]);
          setLoading(false);
          setError(null);
        }).catch(function (err) {
          setLoading(false);
          setError("Failed to connect to Aegis API: " + (err.message || err));
        });
      }, []);

      // Slightly-throttled fetch for refresh-after-scan
      var throttledFetch = useCallback(throttle(fetchAll, 1000), [fetchAll]);

      // Initial load + polling
      useEffect(function () {
        fetchAll();
        pollRef.current = setInterval(fetchAll, POLL_MS);
        return function () {
          if (pollRef.current) clearInterval(pollRef.current);
        };
      }, [fetchAll]);

      // On-demand scan
      var doScan = useCallback(function () {
        var text = scanText;
        if (!text || text.trim().length < 3) return;
        setScanning(true);
        api(BASE + "/scan", {
          method: "POST",
          body: JSON.stringify({ text: text })
        }).then(function (result) {
          setScanResult(result);
          setScanning(false);
          throttledFetch();
        }).catch(function (err) {
          setScanning(false);
          setError("Scan failed: " + (err.message || err));
        });
      }, [scanText, throttledFetch]);

      // Handle Cmd/Ctrl+Enter
      var handleKeyDown = useCallback(function (e) {
        if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
          doScan();
        }
      }, [doScan]);

      // ── Render ─────────────────────────────────────────────────────

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
              "\u26A0 ", error
            ),
            h("div", { style: { textAlign: "center", marginTop: "1rem" } },
              h(Button, { onClick: fetchAll }, "Retry")
            )
          )
        );
      }

      var s = stats || {};
      var sc = s.severity_counts || {};
      var engineHits = engines ? engines.engine_hit_counts || {} : {};
      var categoryHits = engines ? engines.category_counts || {} : {};
      var eMax = 1;
      Object.keys(engineHits).forEach(function (k) { if (engineHits[k] > eMax) eMax = engineHits[k]; });
      var cMax = 1;
      Object.keys(categoryHits).forEach(function (k) { if (categoryHits[k] > cMax) cMax = categoryHits[k]; });

      return h("div", null,

        // ── Header ──────────────────────────────────────────────
        h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" } },
          h("div", { style: { display: "flex", alignItems: "center", gap: "0.75rem" } },
            h("h3", { style: { margin: 0, fontSize: "1.1rem", fontWeight: 700 } }, "Aegis Threat Lab"),
            h("span", { style: { fontSize: "0.7rem", color: "var(--color-muted-foreground)", fontFamily: "var(--font-mono, monospace)" } },
              "v" + (s.version || "\u2014"))
          ),
          h("div", { style: { display: "flex", gap: "0.5rem", alignItems: "center" } },
            h("span", { style: { fontSize: "0.7rem", color: "var(--color-muted-foreground)" } }, "live"),
            h("span", { style: { width: 8, height: 8, borderRadius: "50%", background: "var(--color-success, #22c55e)", display: "inline-block" }})
          )
        ),

        // ── Scan input ───────────────────────────────────────────
        h("div", { className: "aegis-scan-area" },
          h("textarea", {
            value: scanText,
            placeholder: "Paste text to scan for threats\u2026",
            onChange: function (e) { setScanText(e.target.value); },
            onKeyDown: handleKeyDown
          }),
          h(Button, {
            onClick: doScan,
            disabled: scanning || !scanText || scanText.trim().length < 3,
            variant: "default",
            size: "sm"
          }, scanning ? "Scanning\u2026" : "Scan")
        ),

        // Scan result
        scanResult ? h(ScanResultDisplay, { result: scanResult }) : null,

        // ── Stats cards ──────────────────────────────────────────
        h("div", { className: "aegis-grid" },
          h(StatCard, { value: s.scans_total || 0, label: "Total scans" }),
          h(StatCard, { value: s.scans_clean || 0, label: "Clean", success: true }),
          h(StatCard, { value: s.scans_flagged || 0, label: "Flagged", warning: true }),
          h(StatCard, { value: s.scans_blocked || 0, label: "Blocked", danger: true }),
          h(StatCard, { value: (s.avg_duration_ms || 0).toFixed(1) + "ms", label: "Avg duration" })
        ),

        // ── Severity distribution ────────────────────────────────
        h(Card, null,
          h(CardContent, null,
            h("div", { className: "aegis-section-title" }, "Severity Distribution"),
            h(SeverityBars, { counts: sc })
          )
        ),

        // ── Engines + Categories rows ────────────────────────────
        h("div", { className: "aegis-row" },

          // Engine hit rates
          h(Card, null,
            h(CardContent, null,
              h("div", { className: "aegis-section-title" }, "Engine Hit Rates"),
              Object.keys(engineHits).length === 0
                ? h("div", { className: "aegis-empty" }, "No flagged engines yet")
                : h("table", { className: "aegis-engine-table" },
                    h("thead", null,
                      h("tr", null,
                        h("th", null, "Engine"),
                        h("th", null, "Hits"),
                        h("th", null, "")
                      )
                    ),
                    h("tbody", null,
                      Object.keys(engineHits).sort(function (a, b) { return engineHits[b] - engineHits[a]; }).slice(0, 12).map(function (name) {
                        return h(EngineRow, { key: name, name: shorten(name, 32), count: engineHits[name], maxVal: eMax });
                      })
                    )
                  )
            )
          ),

          // Category breakdown
          h(Card, null,
            h(CardContent, null,
              h("div", { className: "aegis-section-title" }, "Threat Categories"),
              Object.keys(categoryHits).length === 0
                ? h("div", { className: "aegis-empty" }, "No threats detected yet")
                : h("table", { className: "aegis-engine-table" },
                    h("thead", null,
                      h("tr", null,
                        h("th", null, "Category"),
                        h("th", null, "Count"),
                        h("th", null, "")
                      )
                    ),
                    h("tbody", null,
                      Object.keys(categoryHits).sort(function (a, b) { return categoryHits[b] - categoryHits[a]; }).map(function (name) {
                        return h(EngineRow, { key: name, name: name, count: categoryHits[name], maxVal: cMax });
                      })
                    )
                  )
            )
          )
        ),

        // ── Recent alerts ─────────────────────────────────────────
        h(Card, null,
          h(CardHeader, null,
            h(CardTitle, { className: "aegis-section-title", style: { margin: 0 } },
              "Recent Alerts", " ",
              h("span", { style: { fontSize: "0.7rem", fontWeight: 400, color: "var(--color-muted-foreground)" } },
                "(" + (alerts.length || 0) + ")"
              )
            )
          ),
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

    // ── Register the plugin tab ──────────────────────────────────────────────
    if (P && typeof P.register === "function") {
      P.register("aegis-latent", AegisThreatLab);
    } else {
      // Fallback: use global registry or just render inline
      console.log("[aegis-latent] SDK register unavailable, tab not registered");
    }
  }

  // Start the init chain — retries until SDK/React is ready
  init();

})();
