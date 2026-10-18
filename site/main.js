/* cloudfs landing — minimal behavior: scroll reveals, copy button, year. */
(function () {
  "use strict";

  /* ----- scroll reveals (no-JS fallback: reveal everything) ----- */
  var revealables = document.querySelectorAll(".reveal");
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!("IntersectionObserver" in window) || reduced) {
    revealables.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("in");
            io.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    revealables.forEach(function (el) { io.observe(el); });
  }

  /* ----- copy-to-clipboard on the quickstart terminal ----- */
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var pre = btn.closest(".terminal");
      pre = pre && pre.querySelector("code");
      if (!pre || !navigator.clipboard) return;
      navigator.clipboard.writeText(pre.innerText).then(function () {
        btn.textContent = "copied";
        btn.classList.add("is-copied");
        setTimeout(function () {
          btn.textContent = "copy";
          btn.classList.remove("is-copied");
        }, 1600);
      });
    });
  });

  /* ----- footer year ----- */
  var year = document.querySelector("[data-year]");
  if (year) year.textContent = String(new Date().getFullYear());
})();
