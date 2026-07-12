"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  const t = await r.text();
  let data; try { data = t ? JSON.parse(t) : null; } catch { data = t; }
  if (!r.ok) throw new Error((data && data.detail) || (data && data.error) || r.statusText);
  return data;
};
const jpost = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const statusClass = (s) => "status-" + Math.floor((s || 0) / 100);
const parseHeaders = (txt) => {
  const h = {};
  (txt || "").split("\n").forEach((line) => {
    const i = line.indexOf(":");
    if (i > 0) h[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return h;
};
const fmtHeaders = (obj) => Object.entries(obj || {}).map(([k, v]) => `${k}: ${v}`).join("\n");

// ---- tabs ----
$$("#tabs button").forEach((b) => b.onclick = () => {
  $$("#tabs button").forEach((x) => x.classList.remove("active"));
  $$(".tab").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  $("#" + b.dataset.tab).classList.add("active");
  if (b.dataset.tab === "history") loadHistory();
  if (b.dataset.tab === "intercept") loadIntercept();
});

// ---- proxy bar ----
async function refreshProxy() {
  const s = await api("/api/proxy/status");
  const ca = await api("/api/proxy/ca");
  const bar = $("#proxybar");
  bar.innerHTML = s.running
    ? `<span class="dot on"></span> Proxy on <code>${s.host}:${s.port}</code>
       <button class="ghost" id="proxyStop">Stop</button>
       <a href="/api/proxy/ca/download"><button class="ghost">Download CA</button></a>`
    : `<span class="dot off"></span> Proxy off
       <input id="proxyPort" type="number" value="8080" style="width:6em" />
       <button id="proxyStart">Start proxy</button>` +
      (s.error ? ` <span class="hint" style="color:var(--danger)">${s.error}</span>` : "");
  if ($("#proxyStart")) $("#proxyStart").onclick = async () => {
    await jpost("/api/proxy/start", { port: +$("#proxyPort").value }); setTimeout(refreshProxy, 400);
  };
  if ($("#proxyStop")) $("#proxyStop").onclick = async () => { await jpost("/api/proxy/stop", {}); refreshProxy(); };
}

// ---- history ----
let histSel = null;
async function loadHistory() {
  const host = $("#histFilter").value.trim();
  const rows = await api("/api/flows?limit=300" + (host ? "&host=" + encodeURIComponent(host) : ""));
  const tb = $("#histTable tbody"); tb.innerHTML = "";
  rows.forEach((f) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${f.id}</td><td>${f.method}</td><td>${f.host}</td>
      <td title="${f.path || ""}">${f.path || ""}</td>
      <td class="${statusClass(f.status)}">${f.status || "-"}</td><td>${f.resp_length ?? ""}</td>`;
    tr.onclick = () => showFlow(f.id, tr);
    tb.appendChild(tr);
  });
}
async function showFlow(id, tr) {
  $$("#histTable tr").forEach((x) => x.classList.remove("sel"));
  if (tr) tr.classList.add("sel");
  const f = await api("/api/flows/" + id);
  const reqLine = `${f.method} ${f.url}`;
  $("#histDetail").innerHTML =
    `<div class="row"><button class="ghost" id="toRepeater">Send to Repeater</button>
       <button class="ghost" id="toFuzzer">Send to Fuzzer</button></div>
     <h4>Request</h4><pre>${esc(reqLine)}\n${esc(fmtHeaders(f.req_headers))}\n\n${esc(f.req_body || "")}</pre>
     <h4>Response — <span class="${statusClass(f.status)}">${f.status}</span>
       (${f.resp_length} bytes, ${f.duration_ms ? f.duration_ms.toFixed(0) + " ms" : "-"})</h4>
     <pre>${esc(fmtHeaders(f.resp_headers))}\n\n${esc((f.resp_body || "").slice(0, 20000))}</pre>`;
  $("#toRepeater").onclick = () => sendToRepeater(f);
  $("#toFuzzer").onclick = () => sendToFuzzer(f);
}
$("#histRefresh").onclick = loadHistory;
$("#histFilter").oninput = () => { clearTimeout(window._ht); window._ht = setTimeout(loadHistory, 300); };
$("#histClear").onclick = async () => { if (confirm("Clear all history?")) { await api("/api/flows", { method: "DELETE" }); loadHistory(); } };

// ---- intercept ----
async function loadIntercept() {
  const s = await api("/api/intercept");
  $("#interceptToggle").checked = s.enabled;
  updateBadge(s.pending.length);
  const box = $("#pendingList"); box.innerHTML = "";
  if (!s.pending.length) { box.innerHTML = "<p class='hint'>No paused requests.</p>"; return; }
  s.pending.forEach((p) => {
    const el = document.createElement("div"); el.className = "pending";
    el.innerHTML =
      `<div class="row"><b>#${p.id}</b> <code>${p.method}</code> ${esc(p.url)}</div>
       <label>Headers</label><textarea data-h>${esc(fmtHeaders(p.headers))}</textarea>
       <label>Body</label><textarea data-b>${esc(p.body || "")}</textarea>
       <div class="row"><button data-fwd>Forward ▶</button>
         <button class="danger" data-drop>Drop</button></div>`;
    $("[data-fwd]", el).onclick = async () => {
      await jpost(`/api/intercept/${p.id}/forward`, {
        method: p.method, url: p.url,
        headers: parseHeaders($("[data-h]", el).value), body: $("[data-b]", el).value,
      });
      loadIntercept();
    };
    $("[data-drop]", el).onclick = async () => { await jpost(`/api/intercept/${p.id}/drop`, {}); loadIntercept(); };
    box.appendChild(el);
  });
}
$("#interceptToggle").onchange = async (e) => { await jpost("/api/intercept/toggle", { enabled: e.target.checked }); loadIntercept(); };
function updateBadge(n) {
  const b = $("#pendingBadge"); b.textContent = n;
  b.classList.toggle("hidden", !n);
}

// ---- repeater ----
function sendToRepeater(f) {
  $$("#tabs button").find = null;
  $("#tabs button[data-tab=repeater]").click();
  $("#rMethod").value = f.method; $("#rUrl").value = f.url;
  $("#rHeaders").value = fmtHeaders(f.req_headers); $("#rBody").value = f.req_body || "";
}
$("#rSend").onclick = async () => {
  $("#rResp").innerHTML = "<em>sending…</em>";
  try {
    const r = await jpost("/api/repeater/send", {
      method: $("#rMethod").value, url: $("#rUrl").value.trim(),
      headers: parseHeaders($("#rHeaders").value), body: $("#rBody").value,
    });
    $("#rResp").innerHTML =
      `<b class="${statusClass(r.status)}">${r.status} ${esc(r.reason || "")}</b>  ` +
      `<span class="hint">${r.length} bytes · ${r.duration_ms} ms</span>\n\n` +
      esc(fmtHeaders(r.headers)) + "\n\n" + esc((r.body || "").slice(0, 50000));
  } catch (e) { $("#rResp").innerHTML = `<span style="color:var(--danger)">${esc(e.message)}</span>`; }
};

// ---- fuzzer ----
function sendToFuzzer(f) {
  $("#tabs button[data-tab=fuzzer]").click();
  $("#fMethod").value = f.method; $("#fUrl").value = f.url;
  $("#fHeaders").value = fmtHeaders(f.req_headers); $("#fBody").value = f.req_body || "";
}
$("#fStart").onclick = async () => {
  const payloads = $("#fPayloads").value.split("\n").map((x) => x).filter((x) => x.length);
  $("#fTable tbody").innerHTML = ""; $("#fProgress").textContent = "starting…";
  try {
    const { job_id } = await jpost("/api/fuzzer/start", {
      method: $("#fMethod").value, url: $("#fUrl").value.trim(), marker: $("#fMarker").value,
      headers: parseHeaders($("#fHeaders").value), body: $("#fBody").value,
      payloads, concurrency: +$("#fConc").value,
    });
    pollFuzz(job_id);
  } catch (e) { $("#fProgress").innerHTML = `<span style="color:var(--danger)">${esc(e.message)}</span>`; }
};
async function pollFuzz(jobId) {
  const job = await api("/api/fuzzer/" + jobId);
  $("#fProgress").textContent = `${job.done}/${job.total} — ${job.status}`;
  const tb = $("#fTable tbody"); tb.innerHTML = "";
  job.results.forEach((e) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${e.index}</td><td title="${esc(e.payload)}">${esc(e.payload)}</td>
      <td class="${statusClass(e.status)}">${e.error ? "ERR" : e.status}</td>
      <td>${e.length}</td><td>${e.duration_ms ?? ""}</td>`;
    if (e.error) tr.title = e.error;
    tb.appendChild(tr);
  });
  if (job.status === "running") setTimeout(() => pollFuzz(jobId), 500);
}

// ---- scope ----
async function loadScope() {
  const s = await api("/api/scope");
  $("#scopeEnabled").checked = s.enabled; $("#scopeHosts").value = s.hosts.join("\n");
}
$("#scopeSave").onclick = async () => {
  const s = await jpost("/api/scope", {
    enabled: $("#scopeEnabled").checked,
    hosts: $("#scopeHosts").value.split("\n").map((x) => x.trim()).filter(Boolean),
  });
  $("#scopeMsg").textContent = `saved — ${s.enabled ? "enforcing" : "off"}, ${s.hosts.length} host(s)`;
};

function esc(s) { return String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

// ---- boot ----
refreshProxy(); loadHistory(); loadScope();
setInterval(async () => { try { const s = await api("/api/intercept"); updateBadge(s.pending.length); } catch {} }, 1500);
