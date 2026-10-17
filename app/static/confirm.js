// Ask before submitting destructive forms (CSP blocks inline handlers).
document.querySelectorAll("form.confirm").forEach(function (f) {
  f.addEventListener("submit", function (ev) {
    if (!window.confirm(f.dataset.confirm || "Are you sure?")) ev.preventDefault();
  });
});
