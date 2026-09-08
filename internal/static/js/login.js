(function () {
  var tabs = document.querySelectorAll('.tab');
  var forms = document.querySelectorAll('.auth-form');

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      var panel = tab.getAttribute('data-panel');

      tabs.forEach(function (t) {
        var active = t === tab;
        t.classList.toggle('is-active', active);
        t.setAttribute('aria-selected', active ? 'true' : 'false');
      });

      forms.forEach(function (form) {
        form.classList.toggle('is-active', form.id === panel);
      });
    });
  });
})();
