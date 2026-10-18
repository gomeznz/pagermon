// Sign-in background: the transmitter eases after the pointer (or wanders when
// there is none), the grid lights up around the pointer, and clicks send a burst.
(function () {
  "use strict";
  const bg = document.getElementById("lbg");
  if (!bg) return;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  let w = window.innerWidth, h = window.innerHeight;
  let mx = w / 2, my = h * 0.42;           // pointer
  let tx = mx, ty = my;                    // transmitter
  let lastMove = 0, raf = 0, t0 = performance.now();

  function set(name, v) { bg.style.setProperty(name, v); }

  function frame(now) {
    raf = 0;
    if (document.hidden || reduce.matches) return;
    const idle = now - lastMove > 4000;
    let goalX = mx, goalY = my;
    if (idle) {
      // Drift on a slow figure-of-eight so the page stays alive on touch screens.
      const t = (now - t0) / 1000;
      goalX = w * (0.5 + 0.28 * Math.sin(t * 0.21));
      goalY = h * (0.45 + 0.18 * Math.sin(t * 0.42));
      mx += (goalX - mx) * 0.02; my += (goalY - my) * 0.02;
    }
    tx += (goalX - tx) * 0.06;
    ty += (goalY - ty) * 0.06;
    set("--tx", tx.toFixed(1) + "px");
    set("--ty", ty.toFixed(1) + "px");
    set("--mx", mx.toFixed(1) + "px");
    set("--my", my.toFixed(1) + "px");
    set("--px", ((mx / w) * 2 - 1).toFixed(3));
    set("--py", ((my / h) * 2 - 1).toFixed(3));
    raf = requestAnimationFrame(frame);
  }
  function kick() { if (!raf && !document.hidden && !reduce.matches) raf = requestAnimationFrame(frame); }

  function burst(x, y) {
    if (reduce.matches) return;
    const b = document.createElement("span");
    b.className = "lbg-burst";
    b.style.left = x + "px";
    b.style.top = y + "px";
    b.addEventListener("animationend", function () { b.remove(); });
    bg.appendChild(b);
    if (bg.querySelectorAll(".lbg-burst").length > 8) bg.querySelector(".lbg-burst").remove();
  }

  window.addEventListener("pointermove", function (e) {
    mx = e.clientX; my = e.clientY; lastMove = performance.now(); kick();
  }, { passive: true });
  window.addEventListener("pointerdown", function (e) {
    // Burst wherever the user clicks or taps, except inside the sign-in form.
    if (!e.target.closest(".login-card")) burst(e.clientX, e.clientY);
    mx = e.clientX; my = e.clientY; lastMove = performance.now(); kick();
  }, { passive: true });
  window.addEventListener("resize", function () { w = window.innerWidth; h = window.innerHeight; kick(); });
  document.addEventListener("visibilitychange", kick);
  reduce.addEventListener("change", kick);
  kick();
})();
