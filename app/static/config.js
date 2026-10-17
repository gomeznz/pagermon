// Copy kiosk links to the clipboard.
document.querySelectorAll(".copy-link").forEach(function (btn) {
  btn.addEventListener("click", function () {
    const input = btn.parentElement.querySelector("input");
    const done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy"; }, 1500); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(input.value).then(done, function () { input.select(); });
    } else {
      input.select();
      try { if (document.execCommand("copy")) done(); } catch (e) { /* leave it selected */ }
    }
  });
});
