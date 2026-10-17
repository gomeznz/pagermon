// Kiosk display: read-only live pages for a wall screen. Text is inserted with textContent only.
(function () {
  "use strict";
  const MAX_CARDS = 50;
  const ALERT_GLOW_MS = 120000; // alert pages pulse for two minutes after arriving
  const list = document.getElementById("k-list");
  const empty = document.getElementById("k-empty");
  const banner = document.getElementById("k-banner");
  const statusEl = document.getElementById("k-status");
  const statusText = document.getElementById("k-status-text");
  const fsBtn = document.getElementById("k-fs");
  const token = location.pathname.split("/")[2] || "";
  const seen = new Set();
  let retry = 1000;
  let loaded = false;

  function pad(n) { return String(n).padStart(2, "0"); }
  function tick() {
    const d = new Date();
    document.getElementById("k-time").textContent = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    document.getElementById("k-date").textContent = d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" });
  }
  tick();
  setInterval(tick, 1000);

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }
  function colourClass(c) { return /^[a-z]+$/.test(c || "") ? " c-" + c : ""; }

  function messageBody(m) {
    const p = el("div", "k-msg");
    if (!m.message) { p.appendChild(el("span", "k-tone", m.msg_type === "tone" ? "Tone only" : "(" + m.msg_type + ")")); return p; }
    let pos = 0;
    for (const s of (m.spans || [])) {
      if (s[0] > pos) p.appendChild(document.createTextNode(m.message.slice(pos, s[0])));
      p.appendChild(el("mark", "kw" + colourClass(s[2]), m.message.slice(s[0], s[1])));
      pos = s[1];
    }
    if (pos < m.message.length) p.appendChild(document.createTextNode(m.message.slice(pos)));
    return p;
  }

  function card(m, fresh) {
    const a = el("article", "k-card" + colourClass(m.colour) + (m.alert ? " is-alert" : "") + (fresh ? " is-new" : ""));
    const head = el("div", "k-head");
    head.appendChild(el("span", "k-time", (m.time || "").slice(11)));
    const who = el("span", "k-who");
    who.appendChild(el("span", "k-alias", m.alias || m.capcode));
    if (m.alias) who.appendChild(el("span", "k-cap", m.capcode));
    head.appendChild(who);
    if (m.alert) head.appendChild(el("span", "k-alert", "ALERT"));
    head.appendChild(el("span", "k-proto", m.protocol + (m.channel_name ? " · " + m.channel_name : "")));
    a.appendChild(head);
    a.appendChild(messageBody(m));
    if (m.alert && fresh) setTimeout(function () { a.classList.add("alert-settled"); }, ALERT_GLOW_MS);
    else if (m.alert) a.classList.add("alert-settled");
    return a;
  }

  function add(messages) {
    for (const m of messages) {
      if (seen.has(m.id)) continue;
      seen.add(m.id);
      list.insertBefore(card(m, loaded), list.firstChild);
    }
    while (list.children.length > MAX_CARDS) list.removeChild(list.lastChild);
    empty.hidden = list.children.length > 0;
  }

  function setStatus(ok, text) {
    statusEl.className = "k-status " + (ok ? "ok" : "bad");
    statusText.textContent = text;
    statusEl.title = text;
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(proto + location.host + "/kiosk/" + encodeURIComponent(token) + "/ws");
    ws.onopen = function () { retry = 1000; banner.hidden = true; };
    ws.onmessage = function (ev) {
      const data = JSON.parse(ev.data);
      if (data.type === "messages") { add(data.messages); loaded = true; }
      else if (data.type === "status") setStatus(data.decoder === "up", data.decoder === "up" ? "Receiving" : "Receiver offline");
    };
    ws.onclose = function (ev) {
      setStatus(false, "Disconnected");
      banner.hidden = false;
      // If the link has been disabled or replaced, show the "not valid" page
      // instead of retrying forever. Network errors just mean keep retrying.
      fetch(location.href, { cache: "no-store" })
        .then(function (r) { if (r.status === 404) location.reload(); })
        .catch(function () {});
      setTimeout(connect, retry);
      retry = Math.min(retry * 2, 30000);
    };
  }

  // Keep the screen awake where the browser allows it (HTTPS or localhost).
  let wakeLock = null;
  async function keepAwake() {
    try { if ("wakeLock" in navigator && !wakeLock) wakeLock = await navigator.wakeLock.request("screen"); }
    catch (e) { /* not available here */ }
  }
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") { wakeLock = null; keepAwake(); }
  });
  keepAwake();

  // Hide the cursor and the full-screen button when the mouse is idle.
  let idle;
  function wake() {
    document.body.classList.remove("idle");
    clearTimeout(idle);
    idle = setTimeout(function () { document.body.classList.add("idle"); }, 3000);
  }
  ["mousemove", "touchstart", "keydown"].forEach(function (e) { document.addEventListener(e, wake, { passive: true }); });
  wake();
  fsBtn.addEventListener("click", function () {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(function () {});
  });
  document.addEventListener("fullscreenchange", function () {
    fsBtn.textContent = document.fullscreenElement ? "Exit full screen" : "Full screen";
  });

  connect();
})();
