// Ask before submitting destructive forms (CSP blocks inline handlers).
document.querySelectorAll("form.confirm").forEach(function (f) {
  f.addEventListener("submit", function (ev) {
    if (!window.confirm(f.dataset.confirm || "Are you sure?")) ev.preventDefault();
  });
});
// Single buttons inside a larger form (e.g. "Remove keys") confirm on click.
document.querySelectorAll("button[data-confirm]").forEach(function (b) {
  b.addEventListener("click", function (ev) {
    if (!window.confirm(b.dataset.confirm)) ev.preventDefault();
  });
});
