// Shared map drawing for the Map page and kiosk displays (Leaflet).
// All text goes into the map via DOM nodes and textContent, never HTML strings.
window.MPPMap = (function () {
  "use strict";
  const COLOURS = {
    red: "#dc2626", orange: "#ea580c", amber: "#d97706", lime: "#65a30d", green: "#16a34a", teal: "#0d9488",
    cyan: "#0891b2", blue: "#2563eb", indigo: "#4f46e5", purple: "#9333ea", pink: "#db2777", grey: "#64748b"
  };
  const ALERT = "#dc2626";
  const DEFAULT = "#0f766e";

  function colourOf(m) {
    if (m.alert) return ALERT;
    return COLOURS[m.colour] || DEFAULT;
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function create(node, opts) {
    const map = L.map(node, { zoomControl: true, attributionControl: true, worldCopyJump: true });
    const attr = el("span", null, node.dataset.attribution || "");
    L.tileLayer(node.dataset.tiles, {
      maxZoom: 19,
      attribution: attr.innerHTML,          // escaped text
      referrerPolicy: "strict-origin-when-cross-origin"
    }).addTo(map);
    map.setView([-41.2, 172.5], 5);         // New Zealand until there's something to show
    map.attributionControl.setPrefix(false);
    return map;
  }

  function areaText(m) {
    const loc = m.loc;
    if (!loc) return "";
    if (loc.precision === "point") return "exact address";
    const r = loc.radius >= 1000 ? (loc.radius / 1000).toFixed(1) + " km" : Math.round(loc.radius) + " m";
    return (loc.precision === "locality" ? "town/area" : "street") + " · within ≈" + r;
  }

  function popup(m) {
    const box = el("div", "mpp-pop");
    const head = el("div", "mpp-pop-head");
    head.appendChild(el("strong", null, m.alias || m.capcode));
    if (m.alias) head.appendChild(el("span", "mpp-pop-cap", m.capcode));
    if (m.alert) head.appendChild(el("span", "mpp-pop-alert", "ALERT"));
    box.appendChild(head);
    box.appendChild(el("div", "mpp-pop-time", m.time + (m.channel_name ? " · " + m.channel_name : "")));
    box.appendChild(el("div", "mpp-pop-msg", m.message || "(" + m.msg_type + ")"));
    const where = el("div", "mpp-pop-loc");
    where.appendChild(el("span", null, "📍 " + (m.loc.label || "")));
    where.appendChild(el("span", "mpp-pop-prec", areaText(m)));
    box.appendChild(where);
    if (m.loc.display) box.appendChild(el("div", "mpp-pop-display", m.loc.display));
    return box;
  }

  // Draw one page; returns the Leaflet layer (a marker group or circle).
  function layerFor(m) {
    const loc = m.loc;
    const ll = [loc.lat, loc.lon];
    const colour = colourOf(m);
    let layer;
    if (loc.precision === "point") {
      layer = L.circleMarker(ll, {
        radius: m.alert ? 11 : 9, color: "#ffffff", weight: 2.5, fillColor: colour, fillOpacity: 1,
        className: m.alert ? "mpp-pin mpp-alert" : "mpp-pin"
      });
    } else {
      layer = L.featureGroup([
        L.circle(ll, {
          radius: loc.radius, color: colour, weight: 2, dashArray: "6 6", fillColor: colour,
          fillOpacity: m.alert ? 0.22 : 0.13, className: m.alert ? "mpp-area mpp-alert" : "mpp-area"
        }),
        L.circleMarker(ll, { radius: 3.5, color: colour, weight: 0, fillColor: colour, fillOpacity: 0.9 })
      ]);
    }
    layer.bindPopup(function () { return popup(m); }, { maxWidth: 320 });
    return layer;
  }

  function focusOn(map, m, layer, open) {
    if (m.loc.precision === "point") map.flyTo([m.loc.lat, m.loc.lon], Math.max(map.getZoom(), 16), { duration: 0.8 });
    else map.flyToBounds(L.latLng(m.loc.lat, m.loc.lon).toBounds(m.loc.radius * 2).pad(0.25), { duration: 0.8 });
    if (open) setTimeout(function () { layer.openPopup ? layer.openPopup() : null; }, 850);
  }

  // Pages repeated for the same incident share one shape on the map.
  function keyOf(m) {
    return m.loc.lat.toFixed(5) + "," + m.loc.lon.toFixed(5) + "," + (m.loc.radius || 0);
  }

  return { create: create, layerFor: layerFor, focusOn: focusOn, areaText: areaText, colourOf: colourOf, el: el, keyOf: keyOf };
})();
