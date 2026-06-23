/* Aegis Threat Lab — Hermes Memory UI dashboard plugin.
 * Uses Hermes Plugin SDK (window.__HERMES_PLUGIN_SDK__).
 * No build step — plain IIFE, loads dashboard/data/stats.json every 4s.
 */

(function () {
  "use strict";

  /* ── SDK setup ────────────────────────────────────────────────────── */
  var SDK = window.__HERMES_PLUGIN_SDK__;
  var React = SDK.React;
  var h = React.createElement;
  var useState = SDK.hooks.useState;
  var useEffect = SDK.hooks.useEffect;
  var useCallback = SDK.hooks.useCallback;
  var Card = SDK.components.Card;
  var CardHeader = SDK.components.CardHeader;
  var CardTitle = SDK.components.CardTitle;
  var CardContent = SDK.components.CardContent;
  var Badge = SDK.components.Badge;
  var cn = SDK.utils.cn;

  /* ── Derive plugin data directory from this script's URL ─────────── */
  var thisScript = document.currentScript;
  var pluginBase = thisScript ? thisScript.src.replace(/\/dist\/index\.js$/, "") : "";
  var DATA_FILE = pluginBase + "/data/stats.json";
  var POLL_MS = 4000;

  /* ── helpers ──────────────────────────────────────────────────────── */

  function shorten(t, n) {
    if (!t) return "";
    return t.length <= n ? t : t.slice(0, n) + "\u2026";
  }

  /* ── severity colors ──────────────────────────────────────────────── */

  var SEV_MAP = { critical: "destructive", high: "warning", medium: "default", low: "secondary" };

  /* ── Sub-components ─────────────────────────────────────────────────── */

  function AlertItem(props) {
    var a = props.alert;
    var sev = (a.severity || "info").toLowerCase();
    var variant = SEV_MAP[sev] || "outline";
    var engines = a.flagged_engines;
    if (!engines || !engines.length) engines = [];

    return h("div", { className: cn("border border-border rounded p-3", "aegis-alert-item") },
      h("div", { className: cn("flex items-center gap-2 mb-1 text-xs") },
        h(Badge, { variant: variant }, sev),
        h("span", { className: "text-muted-foreground" }, a.time_ago || a.timestamp || ""),
        h("span", { className: "font-mono" }, a.verdict || "flag"),
        a.tool
          ? h(Badge, { variant: "outline", className: "ml-auto" }, a.tool)
          : null
      ),
      h("div", { className: cn("text-sm break-words leading-relaxed", "aegis-alert-text") },
        shorten(a.text_snippet || a.content || "", 400)
      ),
      engines.length
        ? h("div", { className: cn("flex flex-wrap gap-1 mt-1") },
            engines.map(function (e, i) {
              return h(Badge, { key: i, variant: "outline", className: "text-[10px]" }, e);
            })
          )
        : null
    );
  }

  /* ── Parse raw JSON into flat display object ────────────────────────── */
  /* Python writes root-level keys:
   *   scans_total, scans_clean, scans_flagged, scans_blocked,
   *   total_duration_ms, severity_counts, engine_hit_counts,
   *   category_counts, alerts
   */

  function parseStore(raw) {
    if (!raw || typeof raw !== "object") return null;
    return {
      scans_total: raw.scans_total || 0,
      scans_clean: raw.scans_clean || 0,
      scans_flagged: raw.scans_flagged || 0,
      scans_blocked: raw.scans_blocked || 0,
      avg_duration_ms: raw.scans_total > 0
        ? ((raw.total_duration_ms || 0) / raw.scans_total).toFixed(1)
        : "0.0",
      severity_counts: raw.severity_counts || {},
      engine_hit_counts: raw.engine_hit_counts || {},
      category_counts: raw.category_counts || {},
      alerts: raw.alerts || [],
      version: raw.version || "",
      last_scan_at: raw.last_scan_at || null
    };
  }

  /* ── Main tab component ──────────────────────────────────────────────── */

  function AegisThreatLab() {
    var state = useState({
      store: null,
      loading: true,
      fetchError: null
    });
    var data = state[0];
    var setData = state[1];
    var stats = data.store;

    var poll = useCallback(function () {
      SDK.fetchJSON(DATA_FILE).then(function (d) {
        var parsed = parseStore(d);
        if (!parsed) {
          setData({ store: null, loading: false, fetchError: "Empty or invalid JSON" });
          return;
        }
        setData({ store: parsed, loading: false, fetchError: null });
      }).catch(function (err) {
        setData(function (prev) {
          return {
            store: prev.store,
            loading: false,
            fetchError: err ? String(err) : "Fetch failed"
          };
        });
      });
    }, []);

    useEffect(function () {
      poll();
      var id = setInterval(poll, POLL_MS);
      return function () { clearInterval(id); };
    }, [poll]);

    if (data.loading) {
      return h(Card, null,
        h(CardContent, { className: "flex items-center justify-center py-12" },
          h("span", { className: "text-muted-foreground text-sm" }, "Loading\u2026")
        )
      );
    }

    if (data.fetchError) {
      return h(Card, null,
        h(CardContent, { className: "flex items-center justify-center py-12" },
          h("div", { className: "flex flex-col items-center gap-2" },
            h("span", { className: "text-muted-foreground text-sm" }, data.fetchError),
            h("code", { className: "text-xs text-muted-foreground bg-muted px-2 py-1 rounded" }, DATA_FILE)
          )
        )
      );
    }

    if (!stats) {
      return h(Card, null,
        h(CardContent, { className: "flex items-center justify-center py-12" },
          h("span", { className: "text-muted-foreground text-sm" }, "No data yet\u2026")
        )
      );
    }

    var running = stats.scans_total > 0;
    var sevOrder = ["critical", "high", "medium", "low"];
    var sevCounts = stats.severity_counts;
    var engineEntries = Object.keys(stats.engine_hit_counts).sort(function (a, b) { return stats.engine_hit_counts[b] - stats.engine_hit_counts[a]; });
    var catEntries = Object.keys(stats.category_counts).sort(function (a, b) { return stats.category_counts[b] - stats.category_counts[a]; });
    var alerts = stats.alerts || [];

    return h("div", { className: cn("flex flex-col gap-6", "aegis-tab") },

      /* ── Header ───────────────────────────────────────────────────── */
      h(Card, null,
        h(CardHeader, { className: "flex flex-row items-center justify-between" },
          h("div", { className: "flex items-center gap-3" },
            h(CardTitle, { className: "text-lg" }, "Aegis Threat Lab"),
            h(Badge, { variant: running ? "default" : "outline" }, running ? "\u25cf Live" : "\u25cb Idle")
          ),
          h(Badge, { variant: "outline" }, stats.version || "v2.5.3")
        ),
        h(CardContent, { className: "flex flex-col gap-4" },
          h("p", { className: "text-sm text-muted-foreground" },
            "AI governance & threat detection \u2014 scans prompts and responses for jailbreaks, prompt injection, malware, credential leaks, and adversarial patterns."
          ),

          /* ── Stat cards ───────────────────────────────────────────── */
          h("div", { className: cn("grid grid-cols-2 md:grid-cols-5 gap-3", "aegis-cards") },
            h("div", { className: cn("border border-border rounded p-3 text-center", "aegis-card") },
              h("div", { className: "text-xs text-muted-foreground mb-1" }, "Total scans"),
              h("div", { className: "text-2xl font-mono" }, stats.scans_total)
            ),
            h("div", { className: cn("border border-border rounded p-3 text-center", "aegis-card-clean") },
              h("div", { className: "text-xs text-muted-foreground mb-1" }, "Clean"),
              h("div", { className: "text-2xl font-mono text-green-500" }, stats.scans_clean)
            ),
            h("div", { className: cn("border border-border rounded p-3 text-center", "aegis-card-flagged") },
              h("div", { className: "text-xs text-muted-foreground mb-1" }, "Flagged"),
              h("div", { className: "text-2xl font-mono text-yellow-500" }, stats.scans_flagged)
            ),
            h("div", { className: cn("border border-border rounded p-3 text-center", "aegis-card-blocked") },
              h("div", { className: "text-xs text-muted-foreground mb-1" }, "Blocked"),
              h("div", { className: "text-2xl font-mono text-red-500" }, stats.scans_blocked)
            ),
            h("div", { className: cn("border border-border rounded p-3 text-center", "aegis-card-duration") },
              h("div", { className: "text-xs text-muted-foreground mb-1" }, "Avg duration"),
              h("div", { className: "text-xl font-mono" }, stats.avg_duration_ms + "ms")
            )
          )
        )
      ),

      /* ── Severity bars ────────────────────────────────────────────── */
      h(Card, null,
        h(CardHeader, null,
          h(CardTitle, { className: "text-base" }, "Severity Distribution")
        ),
        h(CardContent, null,
          h("div", { className: "flex flex-col gap-2" },
            sevOrder.map(function (s) {
              var count = sevCounts[s] || 0;
              return h("div", { key: s, className: "flex items-center gap-3 text-sm" },
                h("span", { className: "w-16 text-right text-muted-foreground font-mono" }, s),
                h("div", { className: "flex-1 h-3 bg-muted rounded overflow-hidden" },
                  h("div", {
                    className: cn("h-full rounded", "aegis-bar", "aegis-bar-" + s),
                    style: { width: Math.min(count * 10, 100) + "%", backgroundColor: s === "critical" ? "#ef4444" : s === "high" ? "#f97316" : s === "medium" ? "#eab308" : "#3b82f6" }
                  })
                ),
                h("span", { className: "w-8 text-right font-mono" }, count)
              );
            })
          )
        )
      ),

      /* ── Two-column: engine hits + categories ──────────────────────── */
      h("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4" },
        h(Card, null,
          h(CardHeader, null,
            h(CardTitle, { className: "text-base" }, "Engine Hit Rates")
          ),
          h(CardContent, null,
            engineEntries.length
              ? h("div", { className: "flex flex-col gap-1 text-sm" },
                  engineEntries.map(function (k) {
                    return h("div", { key: k, className: "flex justify-between items-center border-b border-border/40 py-1" },
                      h("span", { className: "font-mono truncate" }, k),
                      h("span", { className: "font-mono text-muted-foreground" }, stats.engine_hit_counts[k])
                    );
                  })
                )
              : h("span", { className: "text-xs text-muted-foreground" }, "No data")
          )
        ),
        h(Card, null,
          h(CardHeader, null,
            h(CardTitle, { className: "text-base" }, "Threat Categories")
          ),
          h(CardContent, null,
            catEntries.length
              ? h("div", { className: "flex flex-col gap-1 text-sm" },
                  catEntries.map(function (k) {
                    return h("div", { key: k, className: "flex justify-between items-center border-b border-border/40 py-1" },
                      h("span", { className: "font-mono truncate" }, k),
                      h("span", { className: "font-mono text-muted-foreground" }, stats.category_counts[k])
                    );
                  })
                )
              : h("span", { className: "text-xs text-muted-foreground" }, "No data")
          )
        )
      ),

      /* ── Recent alerts ──────────────────────────────────────────────── */
      h(Card, null,
        h(CardHeader, null,
          h(CardTitle, { className: "text-base" }, "Recent Alerts (" + alerts.length + ")")
        ),
        h(CardContent, { className: "flex flex-col gap-2" },
          alerts.length
            ? alerts.map(function (a, i) { return h(AlertItem, { key: i, alert: a }); })
            : h("span", { className: "text-xs text-muted-foreground" }, "No threats detected yet.")
        )
      )
    );
  }

  /* ── Register with Hermes Dashboard ─────────────────────────────────── */
  window.__HERMES_PLUGINS__.register("aegis-latent", AegisThreatLab);
})();
