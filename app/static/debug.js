// Debug console: polls /api/debug for raw decoder lines. Text goes in via textContent only.
(function () {
  "use strict";
  const MAX_LINES = 5000;
  const con = document.getElementById("console");
  const pill = document.getElementById("dbg-pill");
  const filter = document.getElementById("dbg-filter");
  const chSel = document.getElementById("dbg-channel");
  const srcBoxes = Array.from(document.querySelectorAll(".dbg-src"));
  const unparsedOnly = document.getElementById("dbg-unparsed");
  const pauseBtn = document.getElementById("dbg-pause");
  const clearBtn = document.getElementById("dbg-clear");
  const count = document.getElementById("dbg-count");
  const bottomBtn = document.getElementById("dbg-bottom");

  let lastId = 0;
  let paused = false;
  let follow = true;
  let failures = 0;

  function pad(n, w) { return String(n).padStart(w || 2, "0"); }
  function stamp(ts) {
    const d = new Date(ts * 1000);
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds()) + "." + pad(d.getMilliseconds(), 3);
  }

  function span(cls, text) {
    const s = document.createElement("span");
    s.className = cls;
    s.textContent = text;
    return s;
  }

  function lineEl(l) {
    const div = document.createElement("div");
    div.className = "ln k-" + l.kind;
    div.dataset.src = l.source;
    div.dataset.kind = l.kind;
    div.dataset.ch = l.channel_id == null ? "" : String(l.channel_id);
    div.dataset.search = (l.text + " " + l.channel_name).toLowerCase();
    div.appendChild(span("t", stamp(l.ts)));
    div.appendChild(span("c", l.channel_name || "—"));
    div.appendChild(span("s", l.source === "multimon" ? "multimon-ng" : l.source === "decoder" ? "event" : l.source));
    div.appendChild(span("x", l.text));
    if (l.kind === "unparsed") div.title = "MultipagePlus could not parse this line";
    return div;
  }

  function visible(div) {
    const q = filter.value.trim().toLowerCase();
    if (q && !div.dataset.search.includes(q)) return false;
    if (chSel.value && div.dataset.ch !== chSel.value) return false;
    const on = srcBoxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
    if (on.indexOf(div.dataset.src) === -1) return false;
    if (unparsedOnly.checked && div.dataset.kind !== "unparsed") return false;
    return true;
  }

  function refreshCount() {
    let shown = 0;
    let unparsed = 0;
    for (const d of con.children) {
      if (!d.hidden) shown++;
      if (d.dataset.kind === "unparsed") unparsed++;
    }
    count.textContent = shown + " of " + con.children.length + " lines" +
      (unparsed ? " · " + unparsed + " not parsed" : "") + (paused ? " · paused" : "");
  }

  function applyFilters() {
    for (const d of con.children) d.hidden = !visible(d);
    refreshCount();
    if (follow) con.scrollTop = con.scrollHeight;
  }

  function append(lines) {
    if (!lines.length) return;
    const frag = document.createDocumentFragment();
    for (const l of lines) {
      const d = lineEl(l);
      d.hidden = !visible(d);
      frag.appendChild(d);
      lastId = Math.max(lastId, l.id);
    }
    con.appendChild(frag);
    while (con.children.length > MAX_LINES) con.removeChild(con.firstChild);
    refreshCount();
    if (follow) con.scrollTop = con.scrollHeight;
  }

  function setPill(ok, text) {
    pill.className = "pill " + (ok ? "ok" : "bad");
    pill.replaceChildren(span("dot", ""), document.createTextNode(text));
  }

  async function poll() {
    if (!paused) {
      try {
        const r = await fetch("/api/debug?after=" + lastId + (lastId ? "" : "&limit=1000"), { credentials: "same-origin" });
        if (r.status === 401 || r.status === 403) { location.href = "/login?next=/debug"; return; }
        const data = await r.json();
        append(data.lines);
        setPill(data.decoder === "up", data.decoder === "up" ? "Decoder running" : "Decoder not running");
        failures = 0;
      } catch (e) {
        failures++;
        setPill(false, "Connection lost — retrying");
      }
    }
    setTimeout(poll, failures ? Math.min(1000 * 2 ** failures, 15000) : 1000);
  }

  con.addEventListener("scroll", function () {
    follow = con.scrollTop + con.clientHeight >= con.scrollHeight - 24;
    bottomBtn.hidden = follow;
  });
  bottomBtn.addEventListener("click", function () {
    follow = true;
    con.scrollTop = con.scrollHeight;
    bottomBtn.hidden = true;
  });
  pauseBtn.addEventListener("click", function () {
    paused = !paused;
    pauseBtn.textContent = paused ? "Resume" : "Pause";
    pauseBtn.classList.toggle("primary", paused);
    refreshCount();
  });
  clearBtn.addEventListener("click", async function () {
    if (!window.confirm("Clear the stored debug log for everyone?")) return;
    const body = new URLSearchParams({ csrf: clearBtn.dataset.csrf });
    const r = await fetch("/debug/clear", { method: "POST", body: body, credentials: "same-origin" });
    if (r.ok) { con.replaceChildren(); refreshCount(); }
  });
  [filter, chSel, unparsedOnly].concat(srcBoxes).forEach(function (el) {
    el.addEventListener(el === filter ? "input" : "change", applyFilters);
  });

  poll();
})();
