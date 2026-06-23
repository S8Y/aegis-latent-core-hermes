/**
 * aegis-latent — Hermes Dashboard Threat Lab Tab
 *
 * Single IIFE bundle — no build step.
 * Reads threat stats from /dashboard-plugins/aegis-latent/data/stats.json
 * (written to disk by the agent-side __init__.py hooks).
 *
 * Uses window.__HERMES_PLUGIN_SDK__  (or __HERMES_PLUGINS__ fallback)
 * for React, hooks, components.
 * Registers via   window.__HERMES_PLUGINS__.register(name, component).
 *
 * No backend API needed — user plugins cannot mount FastAPI routers
 * (GHSA-5qr3-c538-wm9j).  The JSON file approach works because the
 * dashboard serves plugin directories as static assets.
 */
(function boot() {
  "use strict";

  /* ── Resolve SDK ──────────────────────────────────────────────────── */
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

  var cn = (SDK.utils && SDK.utils.cn) || function (c) { return c; };

  /* ── Config ───────────────────────────────────────────────────────── */
  var DATA_FILE = "/dashboard-plugins/aegis-latent/data/stats.json";
  var POLL_MS   = 5000;

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

  function fetchJSON(url) {
    return fetch(url).then(function (r) {
      if (!r.ok) return null;
      return r.json().catch(function () { return null; });
    });
  }

  /* ── Sub-components ──────────────────────────────────────────────── */

  function StatCard(props) {
    return h(Card, {
      className: "aegis-stat-card" +
        (props.danger  ? " aegis-danger" : "") +
        (props.warning ? " aegis-warning" : "") +
        (props.success ? " aegis-success" : "")
      },
      h("div", { className: "aegis-stat-value" },
        typeof props.value === "number"
          ? props.value.toLocaleString()
          : props.value
      ),
      h("div", { className: "aegis-stat-label" }, props.label)
    );
  }

  function SeverityBars(props) {
    var names  = ["critical", "high", "medium", "low", "clean"];
    var counts = props.counts || {};
    var maxVal = 1;
    names.forEach(function (s) { if ((counts[s] || 0) > maxVal) maxVal = counts[s]; });

    return h("div", { className: "aegis-bars" },
      names.map(function (sev) {
        var c   = counts[sev] || 0;
        var pct = maxVal > 0 ? (c / maxVal) * 100 : 0;
        return h("div", { key: sev,
          className: cn("aegis-bar", "aegis-bar-" + sev),
          style: { height: Math.max(pct, 4) + "%" },
          title: sev + ": " + c
        },
          h("span", { className: "aegis-bar-count" },
            c > 0 ? c.toLocaleString() : ""
          ),
          h("span", { className: "aegis-bar-label" },
            sev === "critical" ? "crit" : sev
          )
        );
      })
    );
  }

  function EngineRow(props) {
    var pct = Math.min((props.count / (props.maxVal || 1)) * 100, 100);
    return h("tr", null,
      h("td", { className: "aegis-cell-name" }, props.name),
      h("td", { className: "aegis-cell-count" }, props.count.toLocaleString()),
      h("td", null,
        h("div", { className: "aegis-engine-bar-bg" },
          h("div", {
            className: "aegis-engine-bar-fill",
            style: { width: pct + "%", background: "var(--color-ring, #3b82f6)" }
          })
        )
      )
    );
  }

  function AlertItem(props) {
    var a   = props.alert;
    var cls = "aegis-alert-item";
    if (a.severity === "critical") cls += " aegis-alert-critical";
    else if (a.severity === "high") cls += " aegis-alert-high";

    return h("div", { className: cls },
      h("div", { className: "aegis-alert-meta" },
        h("span", {
          className: "aegis-alert-severity aegis-alert-severity-" + a.severity,
          style: { color: sevColor(a.severity) }
        }, a.severity),
        h("span", { className: "aegis-alert-time" }, timeAgo(a.timestamp)),
        h(Badge, {
          variant: a.verdict === "block" ? "destructive" : "secondary"
        }, a.verdict)
      ),
      h("div", { className: "aegis-alert-text" }, shorten(a.text_snippet, 120)),
      a.flagged_engines && a.flagged_engines.length
        ? h("div", { className: "aegis-alert-engines" },
            a.flagged_engines.map(function (e) {
              return h("span", { key: e,
                className: "aegis-badge aegis-badge-flag",
                style: { fontSize: "0.6rem" }
              }, shorten(e, 30));
            })
          )
        : null
    );
  }

  /* ── Main tab component ──────────────────────────────────────────── */
  function AegisThreatLab() {
    /* state */
    var sStats   = useState(null),  stats      = sStats[0],   setStats      = sStats[1];
    var sLoad    = useState(true),  loading    = sLoad[0],    setLoading    = sLoad[1];
    var sError   = useState(null),  error      = sError[0],   setError      = sError[1];
    var pollRef  = useRef(null);

    /* ── fetch data from static JSON file ─────────────────────────── */
    var fetchData = useCallback(function () {
      fetchJSON(DATA_FILE).then(function (data) {
        if (data) {
          setStats(data);
          setLoading(false);
          setError(null);
        } else {
          /* File may not exist yet if the agent has never run a scan */
          if (!loading) return; // only show error on first load
          setLoading(false);
          setError("No data yet — the agent has not scanned any messages. Run a conversation or use 'hermes aegis scan <text>' to generate data.");
        }
      });
    }, [loading]);

    /* ── poll on mount ──────────────────────────────────────────── */
    useEffect(function () {
      fetchData();
      pollRef.current = setInterval(fetchData, POLL_MS);
      return function () {
        if (pollRef.current) clearInterval(pollRef.current);
      };
    }, [fetchData]);

    /* ── render ────────────────────────────────────────────────── */
    if (loading) {
      return h(Card, null,
        h(CardContent, { className: "aegis-empty" },
          "Loading Aegis Threat Lab\u2026"
        )
      );
    }

    if (error) {
      return h(Card, null,
        h(CardHeader, null, h(CardTitle, null, "Aegis Threat Lab")),
        h(CardContent, null,
          h("div", { className: "aegis-empty",
            style: { color: "var(--color-muted-foreground)" }
          }, "\u2139 " + error),
          h("div", { style: { textAlign: "center", marginTop: "1rem" } },
            h("span", { style: { fontSize: "0.75rem",
              color: "var(--color-muted-foreground)" }
            }, "Auto-refreshes every 5s \u2014 data appears once the hook fires.")
          )
        )
      );
    }

    var s = stats || {};
    var sevCounts  = s.severity_counts || {};
    var engineHits = s.engine_hit_counts || {};
    var catHits    = s.category_counts  || {};
    var alerts     = s.alerts || [];

    var eMax = 1;
    Object.keys(engineHits).forEach(function (k) {
      if (engineHits[k] > eMax) eMax = engineHits[k];
    });
    var cMax = 1;
    Object.keys(catHits).forEach(function (k) {
      if (catHits[k] > cMax) cMax = catHits[k];
    });

    return h("div", null,

      /* header bar */
      h("div", { className: "aegis-header-bar" },
        h("div", { className: "aegis-header-left" },
          h("h3", { className: "aegis-header-title" }, "Aegis Threat Lab"),
          h("span", { className: "aegis-version" },
            "v" + (s.version || "\u2014")
          )
        ),
        h("div", { className: "aegis-header-right" },
          h("span", { className: "aegis-live-label" }, "live"),
          h("span", { className: "aegis-live-dot" })
        )
      ),

      /* info banner */
      h("div", { className: "aegis-banner" },
        "Threats are detected automatically during agent conversations. ",
        "To scan specific text, use ",
        h("code", null, "hermes aegis scan <text>"),
        " in the CLI."
      ),

      /* stat cards */
      h("div", { className: "aegis-grid" },
        h(StatCard, { value: s.scans_total || 0,   label: "Total scans" }),
        h(StatCard, { value: s.scans_clean || 0,   label: "Clean",    success: true }),
        h(StatCard, { value: s.scans_flagged || 0, label: "Flagged",  warning: true }),
        h(StatCard, { value: s.scans_blocked || 0, label: "Blocked",  danger: true }),
        h(StatCard, {
          value: (s.avg_duration_ms || 0).toFixed(1) + "ms",
          label: "Avg duration"
        })
      ),

      /* severity distribution */
      h(Card, null, h(CardContent, null,
        h("div", { className: "aegis-section-title" },
          "Severity Distribution"
        ),
        h(SeverityBars, { counts: sevCounts })
      )),

      /* engines + categories side-by-side */
      h("div", { className: "aegis-row" },
        h(Card, null, h(CardContent, null,
          h("div", { className: "aegis-section-title" },
            "Engine Hit Rates"
          ),
          Object.keys(engineHits).length === 0
            ? h("div", { className: "aegis-empty" },
                "No flagged engines yet"
              )
            : h("table", { className: "aegis-engine-table" },
                h("thead", null, h("tr", null,
                  h("th", null, "Engine"),
                  h("th", null, "Hits"),
                  h("th", null, "")
                )),
                h("tbody", null,
                  Object.keys(engineHits)
                    .sort(function (a, b) {
                      return engineHits[b] - engineHits[a];
                    })
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
          h("div", { className: "aegis-section-title" },
            "Threat Categories"
          ),
          Object.keys(catHits).length === 0
            ? h("div", { className: "aegis-empty" },
                "No threats detected yet"
              )
            : h("table", { className: "aegis-engine-table" },
                h("thead", null, h("tr", null,
                  h("th", null, "Category"),
                  h("th", null, "Count"),
                  h("th", null, "")
                )),
                h("tbody", null,
                  Object.keys(catHits)
                    .sort(function (a, b) {
                      return catHits[b] - catHits[a];
                    })
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

      /* recent alerts */
      h(Card, null,
        h(CardHeader, null, h(CardTitle, {
          style: { margin: 0, fontSize: "1rem" }
        },
          "Recent Alerts ",
          h("span", { className: "aegis-alert-count" },
            "(" + (alerts.length || 0) + ")"
          )
        )),
        h(CardContent, null,
          alerts.length === 0
            ? h("div", { className: "aegis-empty" },
                "No alerts \u2014 all clear."
              )
            : h("div", { className: "aegis-alerts" },
                alerts.slice(0, 30).map(function (a, i) {
                  return h(AlertItem, {
                    key: a.timestamp || i, alert: a
                  });
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
    setTimeout(boot, 50);
  }
})();
