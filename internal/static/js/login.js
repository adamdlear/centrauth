(function () {
  var panel = document.querySelector(".authpanel");
  if (panel && panel.querySelector(".alert")) {
    panel.classList.add("is-denied");
  }

  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  if (!tabs.length) return;

  function activate(tab) {
    tabs.forEach(function (t) {
      var active = t === tab;
      t.classList.toggle("is-active", active);
      t.setAttribute("aria-selected", active ? "true" : "false");
      t.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll(".auth-form").forEach(function (form) {
      form.hidden = form.id !== tab.getAttribute("data-panel");
    });
  }

  tabs.forEach(function (tab, i) {
    tab.addEventListener("click", function () {
      activate(tab);
    });
    tab.addEventListener("keydown", function (e) {
      var dir = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!dir) return;
      e.preventDefault();
      var next = tabs[(i + dir + tabs.length) % tabs.length];
      activate(next);
      next.focus();
    });
  });
})();
