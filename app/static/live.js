// Live message feed over WebSocket. All text is inserted with textContent.
(function () {
  "use strict";
  const MAX_ROWS = 500;
  const tbody = document.querySelector("#messages tbody");
  const empty = document.getElementById("empty");
  const filter = document.getElementById("filter");
  const chFilter = document.getElementById("channel-filter");
  const hideTone = document.getElementById("hide-tone");
  const pauseBtn = document.getElementById("pause");
  const count = document.getElementById("count");
  const pill = document.getElementById("decoder-pill");
  const chStatus = document.getElementById("channel-status");

  let paused = false;
  let buffered = [];
  let seen = new Set();
  let retry = 1000;
  let loaded = false;

  try {
    hideTone.checked = localStorage.getItem("pm.hideTone") === "1";
  } catch (e) { /* storage unavailable */ }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function row(m) {
    const tr = el("tr", "type-" + m.msg_type);
    tr.dataset.channel = m.channel_id;
    tr.dataset.type = m.msg_type;
    tr.dataset.search = [m.capcode, m.alias || "", m.message, m.protocol].join(" ").toLowerCase();
    tr.appendChild(el("td", "time", m.time));
    tr.appendChild(el("td", null, m.channel_name));
    const p = el("td");
    p.appendChild(el("span", "proto", m.protocol));
    if (m.function) p.appendChild(el("span", "fn", m.function));
    tr.appendChild(p);
    const c = el("td", "cap", m.capcode);
    if (m.alias) c.appendChild(el("span", "alias", m.alias));
    tr.appendChild(c);
    const msg = el("td", "msg");
    if (m.message) msg.textContent = m.message;
    else msg.appendChild(el("span", "muted", "(" + m.msg_type + ")"));
    tr.appendChild(msg);
    return tr;
  }

  function visible(tr) {
    const q = filter.value.trim().toLowerCase();
    if (q && !tr.dataset.search.includes(q)) return false;
    if (chFilter.value && tr.dataset.channel !== chFilter.value) return false;
    if (hideTone.checked && tr.dataset.type === "tone") return false;
    return true;
  }

  function applyFilters() {
    let shown = 0;
    for (const tr of tbody.rows) {
      const v = visible(tr);
      tr.hidden = !v;
      if (v) shown++;
    }
    empty.hidden = tbody.rows.length > 0;
    count.textContent = tbody.rows.length ? shown + " shown" + (paused && buffered.length ? " · " + buffered.length + " waiting" : "") : "";
  }

  function add(messages, fresh) {
    for (const m of messages) {
      if (seen.has(m.id)) continue;
      seen.add(m.id);
      const tr = row(m);
      if (fresh) tr.classList.add("new");
      tbody.insertBefore(tr, tbody.firstChild);
    }
    while (tbody.rows.length > MAX_ROWS) {
      const last = tbody.rows[tbody.rows.length - 1];
      tbody.removeChild(last);
    }
    if (seen.size > MAX_ROWS * 4) {
      seen = new Set(Array.from(seen).slice(-MAX_ROWS * 2));
    }
    applyFilters();
  }

  function showStatus(s) {
    pill.className = "pill " + (s.decoder === "up" ? "ok" : "bad");
    pill.replaceChildren(el("span", "dot"), document.createTextNode(
      s.decoder === "up" ? "Decoder running" : "Decoder not running"));
    chStatus.replaceChildren();
    for (const c of s.channels) {
      const d = el("div", "chan state-" + c.state.replace(/\s+/g, "-"));
      d.appendChild(el("strong", null, c.name));
      d.appendChild(el("span", "mono", c.freq + " MHz"));
      d.appendChild(el("span", "tag", c.state));
      d.appendChild(el("span", "small muted", c.count + " msgs" + (c.last ? " · last " + c.last.slice(11) : "")));
      if (c.detail && c.state !== "running") d.title = c.detail;
      chStatus.appendChild(d);
    }
    if (!s.channels.length) {
      chStatus.appendChild(el("span", "muted small", "No channels configured."));
    }
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(proto + location.host + "/ws");
    ws.onopen = function () { retry = 1000; };
    ws.onmessage = function (ev) {
      const data = JSON.parse(ev.data);
      if (data.type === "messages") {
        if (paused && loaded) { buffered = buffered.concat(data.messages); applyFilters(); }
        else add(data.messages, loaded);
        loaded = true;
      } else if (data.type === "status") {
        showStatus(data);
      }
    };
    ws.onclose = function (ev) {
      pill.className = "pill bad";
      pill.replaceChildren(el("span", "dot"), document.createTextNode("Disconnected — retrying"));
      if (ev.code === 1008) { location.href = "/login?next=/"; return; }
      setTimeout(connect, retry);
      retry = Math.min(retry * 2, 30000);
    };
  }

  pauseBtn.addEventListener("click", function () {
    paused = !paused;
    pauseBtn.textContent = paused ? "Resume" : "Pause";
    pauseBtn.classList.toggle("primary", paused);
    if (!paused && buffered.length) { add(buffered, true); buffered = []; }
    applyFilters();
  });
  filter.addEventListener("input", applyFilters);
  chFilter.addEventListener("change", applyFilters);
  hideTone.addEventListener("change", function () {
    try { localStorage.setItem("pm.hideTone", hideTone.checked ? "1" : "0"); } catch (e) { /* ignore */ }
    applyFilters();
  });

  applyFilters();
  connect();
})();
