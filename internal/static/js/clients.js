(function () {
  var btn = document.getElementById("newclientbtn");
  var panel = document.getElementById("newclient");

  if (btn && panel) {
    btn.addEventListener("click", function () {
      panel.hidden = !panel.hidden;
      btn.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) {
        var first = panel.querySelector("select, input, textarea");
        if (first) first.focus();
      }
    });

    var cancel = panel.querySelector("[data-close]");
    if (cancel) {
      cancel.addEventListener("click", function () {
        panel.hidden = true;
        btn.setAttribute("aria-expanded", "false");
        btn.focus();
      });
    }

    panel.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        panel.hidden = true;
        btn.setAttribute("aria-expanded", "false");
        btn.focus();
      }
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll(".clientrow"), function (row) {
    var expander = row.querySelector(".expander");
    expander.addEventListener("click", function () {
      var open = row.classList.toggle("is-open");
      document.getElementById(row.getAttribute("data-detail")).hidden = !open;
      expander.setAttribute("aria-expanded", String(open));
    });
  });
})();
