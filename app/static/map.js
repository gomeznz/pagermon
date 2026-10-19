// Map page: pages with a location in the chosen time window, refreshed every 15 s.
(function () {
  "use strict";
  const node = document.getElementById("map");
  const list = document.getElementById("map-list");
  const empty = document.getElementById("map-empty");
  const count = document.getElementById("map-count");
  const hoursSel = document.getElementById("map-hours");
  const supBox = document.getElementById("map-suppressed");
  const focusId = parseInt(node.dataset.focus || "0", 10);
  const el = MPPMap.el;
  const map = MPPMap.create(node);
  const group = L.featureGroup().addTo(map);
  const layers = new Map();   // message id -> {item, msg, key}
  const shapes = new Map();   // location key -> {layer, id} (newest page at that spot)
  let last = 0;
  let firstLoad = true;

  try {
    const h = localStorage.getItem("pm.mapHours");
    if (h && !focusId) hoursSel.value = h;
    supBox.checked = localStorage.getItem("pm.mapSup") === "1";
  } catch (e) { /* storage unavailable */ }

  function listItem(m) {
    const li = el("li", "map-item" + (m.alert ? " is-alert" : ""));
    li.style.setProperty("--dot", MPPMap.colourOf(m));
    const top = el("div", "map-item-top");
    top.appendChild(el("span", "map-dot"));
    top.appendChild(el("strong", null, m.alias || m.capcode));
    top.appendChild(el("span", "map-item-time", (m.time || "").slice(5, 16)));
    li.appendChild(top);
    li.appendChild(el("div", "map-item-loc", "📍 " + m.loc.label));
    li.appendChild(el("div", "map-item-msg", m.message || "(" + m.msg_type + ")"));
    li.appendChild(el("div", "map-item-prec", MPPMap.areaText(m)));
    li.tabIndex = 0;
    li.addEventListener("click", function () { focus(m.id, true); });
    li.addEventListener("keydown", function (e) { if (e.key === "Enter") focus(m.id, true); });
    return li;
  }

  function focus(id, open) {
    const entry = layers.get(id);
    if (!entry) return;
    for (const other of list.children) other.classList.remove("is-selected");
    entry.item.classList.add("is-selected");
    const shape = shapes.get(entry.key);
    if (shape && shape.id !== id) {          // an older page at the same spot: show its own details
      group.removeLayer(shape.layer);
      shapes.set(entry.key, { layer: MPPMap.layerFor(entry.msg).addTo(group), id: id });
    }
    MPPMap.focusOn(map, entry.msg, shapes.get(entry.key).layer, open);
  }

  function addAll(msgs) {
    // newest first in the list
    msgs.sort(function (a, b) { return b.id - a.id; });
    for (const m of msgs.slice().reverse()) {
      if (!m.loc) continue;
      const old = layers.get(m.id);
      if (old) old.item.remove();
      const key = MPPMap.keyOf(m);
      const prev = shapes.get(key);
      if (!prev || prev.id <= m.id) {
        if (prev) group.removeLayer(prev.layer);
        shapes.set(key, { layer: MPPMap.layerFor(m).addTo(group), id: m.id });
      }
      const item = listItem(m);
      list.insertBefore(item, list.firstChild);
      layers.set(m.id, { item: item, msg: m, key: key });
    }
    empty.hidden = layers.size > 0;
    count.textContent = layers.size ? layers.size + " page" + (layers.size === 1 ? "" : "s") : "";
  }

  async function load(reset) {
    if (reset) {
      group.clearLayers(); list.replaceChildren(); layers.clear(); shapes.clear(); last = 0;
    }
    const q = new URLSearchParams({ hours: hoursSel.value, suppressed: supBox.checked ? "1" : "0" });
    if (last) q.set("after", last);
    if (focusId) q.set("focus", focusId);
    try {
      const r = await fetch("/api/map?" + q.toString(), { credentials: "same-origin" });
      if (r.status === 401) { location.href = "/login?next=/map"; return; }
      const data = await r.json();
      addAll(data.messages);
      last = data.last;
      if (firstLoad) {
        firstLoad = false;
        if (focusId && layers.has(focusId)) focus(focusId, true);
        else if (layers.size) map.fitBounds(group.getBounds().pad(0.2), { maxZoom: 15 });
      }
    } catch (e) { /* keep showing what we have; retry on the next tick */ }
  }

  hoursSel.addEventListener("change", function () {
    try { localStorage.setItem("pm.mapHours", hoursSel.value); } catch (e) { /* ignore */ }
    firstLoad = true; load(true);
  });
  supBox.addEventListener("change", function () {
    try { localStorage.setItem("pm.mapSup", supBox.checked ? "1" : "0"); } catch (e) { /* ignore */ }
    load(true);
  });
  load(true);
  setInterval(function () { if (!document.hidden) load(false); }, 15000);
})();
