(function () {
  var addBtn = document.getElementById("addapp");
  var panel = document.getElementById("newapp");

  if (addBtn && panel) {
    addBtn.addEventListener("click", function () {
      panel.hidden = !panel.hidden;
      addBtn.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) {
        var first = panel.querySelector("input, textarea");
        if (first) first.focus();
      }
    });

    var cancel = panel.querySelector("[data-close]");
    if (cancel) {
      cancel.addEventListener("click", function () {
        panel.hidden = true;
        addBtn.setAttribute("aria-expanded", "false");
        addBtn.focus();
      });
    }

    panel.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        panel.hidden = true;
        addBtn.setAttribute("aria-expanded", "false");
        addBtn.focus();
      }
    });
  }

  var editor = document.getElementById("scopeedit");
  var input = document.getElementById("scopeinput");
  if (!editor || !input) return;

  function getChips() {
    return Array.prototype.map.call(editor.querySelectorAll(".chip-edit"), function (c) {
      return c.getAttribute("data-value");
    });
  }

  function addChip(value) {
    value = value.trim().toLowerCase().replace(/[, ]+$/, "");
    if (!value) return;
    if (getChips().indexOf(value) !== -1) return;
    var chip = document.createElement("span");
    chip.className = "chip-edit";
    chip.setAttribute("data-value", value);
    chip.textContent = value;
    var x = document.createElement("button");
    x.type = "button";
    x.className = "chip-x";
    x.setAttribute("aria-label", "Remove " + value);
    x.textContent = "×";
    x.addEventListener("click", function () {
      chip.remove();
    });
    chip.appendChild(x);
    editor.insertBefore(chip, input);
  }

  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === "," || e.key === " ") {
      if (input.value.trim()) {
        e.preventDefault();
        addChip(input.value);
        input.value = "";
      }
    } else if (e.key === "Backspace" && !input.value) {
      var chips = editor.querySelectorAll(".chip-edit");
      if (chips.length) chips[chips.length - 1].remove();
    }
  });

  input.addEventListener("blur", function () {
    if (input.value.trim()) {
      addChip(input.value);
      input.value = "";
    }
  });

  editor.addEventListener("click", function () {
    input.focus();
  });

  var form = editor.closest("form");
  if (form) {
    form.addEventListener("submit", function () {
      input.value = getChips().join(" ");
    });
  }
})();
