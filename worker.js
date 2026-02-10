export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // tenant selection via ?tenant=... or header x-tenant
    const tenant =
      (url.searchParams.get("tenant") ||
        request.headers.get("x-tenant") ||
        "public").trim();

    const id = env.HEARTBEAT.idFromName(`tenant:${tenant}`);
    const stub = env.HEARTBEAT.get(id);

    // pass tenant through to the DO
    const headers = new Headers(request.headers);
    headers.set("x-tenant", tenant);

    return stub.fetch(new Request(request, { headers }));
  },
};

export class HeartbeatDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const tenant = (request.headers.get("x-tenant") || "public").trim();

    // CORS
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    // "/" -> "/app" (backwards compatible)
    if (request.method === "GET" && path === "/") {
      const t = url.searchParams.get("tenant");
      const loc = t ? ("/app?tenant=" + encodeURIComponent(t)) : "/app";
      return new Response(null, { status: 302, headers: { Location: loc, ...corsHeaders() } });
    }

    // Dashboard
    if (request.method === "GET" && path === "/app") {
      return new Response(dashboardHtml(tenant), {
        headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders() },
      });
    }

    // Landing (safe sandbox)
    if (request.method === "GET" && path === "/landing") {
      return new Response(landingHtml(), {
        headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders() },
      });
    }

    // ---- Config (premium gate + alerts) ----
    // POST /admin/config  Authorization: Bearer ADMIN_TOKEN
    // Body: { tier: "free"|"premium", alert_webhook_url: "https://..." }
    if (path === "/admin/config" && request.method === "POST") {
      if (!this.env.ADMIN_TOKEN) return json({ ok: false, error: "ADMIN_TOKEN not set" }, 500);

      const auth = request.headers.get("authorization") || "";
      if (auth !== `Bearer ${this.env.ADMIN_TOKEN}`) {
        return json({ ok: false, error: "Unauthorized" }, 401);
      }

      let body = {};
      try { body = await request.json(); } catch (_) {}

      const tier = (body.tier || "free").toString() === "premium" ? "premium" : "free";
      const alert_webhook_url = (body.alert_webhook_url || "").toString().trim() || null;

      const cfg = { tier, alert_webhook_url, updated_at: new Date().toISOString() };
      await this.state.storage.put("cfg", cfg);

      return json({ ok: true, tenant, cfg });
    }

    // GET /config (safe: doesn’t expose secrets)
    if (path === "/config" && request.method === "GET") {
      const cfg = (await this.state.storage.get("cfg")) || { tier: "free", alert_webhook_url: null };
      return json({ ok: true, tenant, cfg });
    }

    // ---- Facts-based heartbeat (integrations groundwork) ----
    // POST /fact  Body: { source, type, entity, meta? }
    if (path === "/fact" && request.method === "POST") {
      let body = {};
      try { body = await request.json(); } catch (_) {}

      const source = (body.source || "").toString().trim();
      const type = (body.type || "").toString().trim();
      const entity = (body.entity || "").toString().trim();
      if (!source || !type || !entity) {
        return json({ ok: false, error: "Missing source/type/entity" }, 400);
      }

      const now = Date.now();
      const fact = {
        ts: now,
        iso: new Date(now).toISOString(),
        source,
        type,
        entity,
        meta: body.meta ?? null,
      };

      const key = "facts:recent";
      const arr = (await this.state.storage.get(key)) || [];
      arr.unshift(fact);
      if (arr.length > 200) arr.length = 200;
      await this.state.storage.put(key, arr);

      return json({ ok: true, tenant, stored: fact });
    }

    // GET /facts
    if (path === "/facts" && request.method === "GET") {
      const arr = (await this.state.storage.get("facts:recent")) || [];
      return json({ ok: true, tenant, count: arr.length, facts: arr });
    }

    // ---- Heartbeat API ----
    // POST /ping (premium: requires signature)
    if (path === "/ping" && request.method === "POST") {
      let body = {};
      try { body = await request.json(); } catch (_) {}

      const id = (body.id || url.searchParams.get("id") || "").trim();
      if (!id) return json({ ok: false, error: "Missing id (JSON {id} or ?id=...)." }, 400);

      const cfg = (await this.state.storage.get("cfg")) || { tier: "free", alert_webhook_url: null };

      const sig = (request.headers.get("x-hb-sig") || "").trim();
      const ts = (request.headers.get("x-hb-ts") || "").trim();

      let verified = false;

      if (cfg.tier === "premium") {
        if (!sig || !ts) {
          return json({ ok: false, error: "Premium requires x-hb-ts and x-hb-sig" }, 401);
        }
        const ok = await verifySignature({
          secret: this.env.HEARTBEAT_SECRET || "",
          tenant,
          id,
          ts,
          sig,
        });
        if (!ok.ok) return json({ ok: false, error: ok.error }, 401);
        verified = true;
      } else {
        // free: signature optional
        if (sig || ts) {
          const ok = await verifySignature({
            secret: this.env.HEARTBEAT_SECRET || "",
            tenant,
            id,
            ts,
            sig,
          });
          if (!ok.ok) return json({ ok: false, error: ok.error }, 401);
          verified = true;
        }
      }

      const now = Date.now();
      const rec = {
        id,
        ts: now,
        iso: new Date(now).toISOString(),
        ip: request.headers.get("CF-Connecting-IP"),
        ua: request.headers.get("User-Agent"),
        meta: body.meta ?? null,
        verified,
      };

      await this.state.storage.put(`hb:${id}`, rec);

      const ids = (await this.state.storage.get("hb:ids")) || [];
      if (!ids.includes(id)) {
        ids.push(id);
        await this.state.storage.put("hb:ids", ids);
      }

      // Alert on transition to OK (e.g. recovery) if premium configured
      const prevState = (await this.state.storage.get(`st:${id}`)) || null;
      const newState = "OK";
      await this.state.storage.put(`st:${id}`, newState);

      if (cfg.tier === "premium" && cfg.alert_webhook_url && prevState && prevState !== newState) {
        this._fireWebhook(cfg.alert_webhook_url, {
          type: "heartbeat.state_change",
          tenant,
          id,
          from: prevState,
          to: newState,
          at: rec.iso,
          last: rec,
        });
      }

      return json({ ok: true, tenant, stored: rec });
    }

    // GET /status?id=...
    if (path === "/status" && request.method === "GET") {
      const id = (url.searchParams.get("id") || "").trim();
      if (!id) return json({ ok: false, error: "Missing ?id=..." }, 400);

      const rec = await this.state.storage.get(`hb:${id}`);
      if (!rec) return json({ ok: false, error: "Unknown id" }, 404);

      const age_ms = Date.now() - rec.ts;
      const state = stateForAgeMs(age_ms);
      await this.state.storage.put(`st:${id}`, state);

      return json({ ok: true, tenant, id, age_ms, state, last: rec });
    }

    // GET /clients
    if (path === "/clients" && request.method === "GET") {
      const ids = (await this.state.storage.get("hb:ids")) || [];
      const now = Date.now();
      const clients = [];

      for (const id of ids) {
        const rec = await this.state.storage.get(`hb:${id}`);
        if (!rec) continue;
        const age_ms = now - rec.ts;
        const state = stateForAgeMs(age_ms);
        clients.push({ id, age_ms, state, last: rec });
      }

      clients.sort((a, b) => a.age_ms - b.age_ms);

      // Premium: alert on any state change (when someone checks /clients)
      const cfg = (await this.state.storage.get("cfg")) || { tier: "free", alert_webhook_url: null };
      if (cfg.tier === "premium" && cfg.alert_webhook_url) {
        for (const c of clients) {
          const prev = (await this.state.storage.get(`st:${c.id}`)) || null;
          if (prev && prev !== c.state) {
            await this.state.storage.put(`st:${c.id}`, c.state);
            this._fireWebhook(cfg.alert_webhook_url, {
              type: "heartbeat.state_change",
              tenant,
              id: c.id,
              from: prev,
              to: c.state,
              at: new Date().toISOString(),
              age_ms: c.age_ms,
              last: c.last,
            });
          } else if (!prev) {
            await this.state.storage.put(`st:${c.id}`, c.state);
          }
        }
      }

      return json({ ok: true, tenant, count: clients.length, clients });
    }

    return json({ ok: false, error: `No route for ${request.method} ${path}` }, 404);
  }

  _fireWebhook(url, payload) {
    this.state.waitUntil(
      fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      }).catch(() => {})
    );
  }
}

// --------- Signature helpers ---------
// Client sends:
//   x-hb-ts: <unix ms>
//   x-hb-sig: <hex hmac_sha256(secret, `${tenant}\n${id}\n${ts}`)>
async function verifySignature({ secret, tenant, id, ts, sig }) {
  if (!secret) return { ok: false, error: "HEARTBEAT_SECRET not set" };
  if (!ts || !sig) return { ok: false, error: "Missing x-hb-ts or x-hb-sig" };

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { ok: false, error: "Invalid x-hb-ts" };

  const now = Date.now();
  const skewMs = Math.abs(now - tsNum);
  if (skewMs > 5 * 60 * 1000) return { ok: false, error: "Timestamp skew too large" };

  const msg = `${tenant}\n${id}\n${ts}`;
  const want = await hmacHex(secret, msg);
  if (!timingSafeEqual(sig.toLowerCase(), want.toLowerCase())) {
    return { ok: false, error: "Bad signature" };
  }
  return { ok: true };
}

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return bufToHex(sig);
}

function bufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// --------- SLA ---------
function stateForAgeMs(ageMs) {
  if (ageMs < 60_000) return "OK";
  if (ageMs < 300_000) return "WARN";
  return "DOWN";
}

// --------- Responses / CORS ---------
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization,x-tenant,x-hb-ts,x-hb-sig",
  };
}

// --------- HTML ---------
function landingHtml() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Heartbeat</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; line-height: 1.4; color:#111; }
    .wrap { max-width: 980px; margin: 0 auto; }
    h1 { font-size: 44px; margin: 18px 0 10px; }
    p { color:#444; font-size: 16px; }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 18px; }
    .card { border: 1px solid #eee; border-radius: 14px; padding: 16px; background: #fff; }
    .tag { display:inline-block; font-size:12px; font-weight:800; padding: 4px 10px; border-radius: 999px; border: 1px solid #eee; }
    .btn { display:inline-block; margin-top: 12px; padding: 10px 12px; border-radius: 10px; border: 1px solid #ddd; text-decoration:none; color:#111; font-weight:800; }
    .btn.primary { background:#111; color:#fff; border-color:#111; }
    ul { margin: 10px 0 0 18px; color:#333; }
    .muted { color:#666; font-size:12px; margin-top: 18px; }
    code { background:#f6f6f6; padding: 2px 6px; border-radius: 6px; }
    @media (max-width: 780px){ .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="tag">Heartbeat</div>
    <h1>Verifiable heartbeat for systems and work.</h1>
    <p>
      A lightweight dashboard that shows what’s alive, what’s degraded, and what’s down — with optional signed pings for credibility.
      Next: facts-based heartbeat (Figma / GitHub / Jira) so activity is backed by evidence.
    </p>

    <div class="grid">
      <div class="card">
        <div class="tag">Free</div>
        <h2>Start monitoring</h2>
        <ul>
          <li>Dashboard</li>
          <li>Unsigned pings allowed</li>
          <li>Per-tenant separation</li>
        </ul>
        <a class="btn" href="/app?tenant=public">Open dashboard</a>
      </div>

      <div class="card">
        <div class="tag">Premium</div>
        <h2>Credibility + alerts</h2>
        <ul>
          <li>Signed pings required</li>
          <li>Webhook alerts on state change</li>
          <li>Facts-based integrations (next)</li>
        </ul>
        <a class="btn primary" href="/app?tenant=public">Upgrade (next)</a>
      </div>
    </div>

    <div class="muted">
      Dashboard: <code>/app</code> • Landing: <code>/landing</code>
    </div>
  </div>
</body>
</html>`;
}

function dashboardHtml(tenant) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Heartbeat</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; line-height: 1.4; }
    h1 { margin: 0 0 8px; font-size: 32px; }
    .muted { color: #555; margin-bottom: 14px; }
    .card { background: #fff; border: 1px solid #eee; border-radius: 12px; padding: 14px; max-width: 1100px; }
    code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    table { border-collapse: collapse; width: 100%; margin-top: 14px; }
    th, td { text-align: left; border-bottom: 1px solid #eee; padding: 10px 8px; vertical-align: top; }
    th { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #666; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .ok { background: #eafff2; color: #0b6; }
    .warn { background: #fff6e5; color: #a60; }
    .bad { background: #ffecec; color: #b00020; }
    .right { text-align: right; }
    .small { font-size: 12px; color: #666; }
    input { padding: 6px 8px; border: 1px solid #ddd; border-radius: 8px; }
    button { padding: 6px 10px; border: 1px solid #ddd; border-radius: 8px; background: #fff; cursor: pointer; }

    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin: 6px 0; }
    .toprow { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-top:10px; }
    .pill { display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:999px; font-weight:800; font-size:12px; border:1px solid #eee; }
    .pill.ok { background:#eafff2; color:#0b6; }
    .pill.warn { background:#fff6e5; color:#a60; }
    .pill.bad { background:#ffecec; color:#b00020; }
    .kv { font-size:12px; color:#666; }

    .dot { width:10px; height:10px; border-radius:999px; display:inline-block; margin-right:8px; vertical-align:middle; }
    .dot.live { background:#0b6; box-shadow:0 0 0 rgba(11,102,0,.4); animation:pulse 1.6s infinite; }
    .dot.mid  { background:#a60; }
    .dot.dead { background:#b00020; }
    @keyframes pulse {
      0% { box-shadow:0 0 0 0 rgba(11,102,0,.35); }
      70% { box-shadow:0 0 0 10px rgba(11,102,0,0); }
      100% { box-shadow:0 0 0 0 rgba(11,102,0,0); }
    }

    .bar { height:6px; background:#f2f2f2; border-radius:999px; overflow:hidden; margin-top:6px; }
    .bar > i { display:block; height:100%; width:0%; }
    .bar > i.ok { background:#0b6; }
    .bar > i.warn { background:#a60; }
    .bar > i.bad { background:#b00020; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Heartbeat</h1>

    <div class="muted">
      <div class="row">
        <span>Tenant:</span>
        <input id="tenant" value="${escapeHtml(tenant)}" />
        <button id="go">Open</button>
      </div>

      <div class="small">
        Ping: <code>POST /ping</code> body <code>{"id":"server-1"}</code><br/>
        List: <code>GET /clients</code> • Status: <code>GET /status?id=server-1</code>
      </div>

      <div class="toprow">
        <span id="overall" class="pill ok">🟢 OK</span>
        <span class="kv" id="meta"></span>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>ID</th><th>State</th><th class="right">Age</th><th>Last seen</th><th>Verified</th><th>IP</th><th>User-Agent</th>
        </tr>
      </thead>
      <tbody id="rows">
        <tr><td colspan="7" class="small">Loading…</td></tr>
      </tbody>
    </table>
  </div>

<script>
  var overallEl = document.getElementById("overall");
  var metaEl = document.getElementById("meta");

  document.getElementById("go").onclick = function(){
    var t = document.getElementById("tenant").value.trim() || "public";
    location.href = "/app?tenant=" + encodeURIComponent(t);
  };

  function fmtAge(ms){
    var s = Math.floor(ms/1000);
    if (s < 60) return s + "s";
    var m = Math.floor(s/60);
    if (m < 60) return m + "m " + (s%60) + "s";
    var h = Math.floor(m/60);
    return h + "h " + (m%60) + "m";
  }

  function badgeFor(state){
    if (state === "OK") return { cls: "ok", label: "OK", dot: "live" };
    if (state === "WARN") return { cls: "warn", label: "WARN", dot: "mid" };
    return { cls: "bad", label: "DOWN", dot: "dead" };
  }

  function overallFrom(list){
    var hasDown = list.some(function(c){ return (c.state || "DOWN") === "DOWN"; });
    var hasWarn = list.some(function(c){ return (c.state || "DOWN") === "WARN"; });
    if (hasDown) return { cls:"bad", txt:"🔴 DOWN" };
    if (hasWarn) return { cls:"warn", txt:"🟠 WARN" };
    return { cls:"ok", txt:"🟢 OK" };
  }

  function barWidth(ageMs){
    return Math.min(100, Math.round((ageMs / 300000) * 100));
  }

  function barColorClass(state){
    if (state === "OK") return "ok";
    if (state === "WARN") return "warn";
    return "bad";
  }

  async function refresh(){
    var t = new URL(location.href).searchParams.get("tenant") || "public";
    var res = await fetch("/clients?tenant=" + encodeURIComponent(t), { cache: "no-store" });
    var data = await res.json();

    var rows = document.getElementById("rows");
    rows.innerHTML = "";

    var list = (data && data.clients) ? data.clients : [];

    var o = overallFrom(list);
    overallEl.className = "pill " + o.cls;
    overallEl.textContent = o.txt;

    metaEl.textContent =
      "Tenant: " + t +
      " • Clients: " + ((data && data.count) ? data.count : 0) +
      " • Updated: " + new Date().toLocaleTimeString();

    if (!list.length) {
      rows.innerHTML = '<tr><td colspan="7" class="small">No clients yet. Send your first ping to <code>/ping</code>.</td></tr>';
      return;
    }

    list.forEach(function(c){
      var b = badgeFor(c.state || "DOWN");
      var tr = document.createElement("tr");
      var last = c.last || {};

      var age = c.age_ms || 0;
      var isFresh = age < 10000;
      var dotCls = b.dot;
      if (!isFresh && dotCls === "live") dotCls = "mid";

      var w = barWidth(age);
      var barCls = barColorClass(c.state || "DOWN");

      var verified = (last.verified
        ? "<span class='pill ok'>Verified</span>"
        : "<span class='pill bad'>Unverified</span>");

      tr.innerHTML =
        "<td><span class='dot " + dotCls + "'></span><code>" + c.id + "</code>" +
          "<div class='bar'><i class='" + barCls + "' style='width:" + w + "%'></i></div></td>" +
        "<td><span class=\\"badge " + b.cls + "\\">" + b.label + "</span></td>" +
        "<td class=\\"right\\">" + fmtAge(age) + "</td>" +
        "<td>" + (last.iso || "") + "</td>" +
        "<td>" + verified + "</td>" +
        "<td>" + (last.ip || "") + "</td>" +
        "<td style=\\"max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;\\">" + (last.ua || "") + "</td>";

      rows.appendChild(tr);
    });
  }

  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
