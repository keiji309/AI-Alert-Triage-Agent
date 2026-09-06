/* Triage Console — minimal progressive-enhancement JS.
   Core flows work without JavaScript; fetch interception just adds
   toasts, loading states, and avoids navigating to JSON responses. */

(function () {
  "use strict";

  var FLASH_MESSAGES = {
    triaged: { text: "Investigation complete — verdict saved.", type: "success" },
    "triaged-all": { text: "All open cases have been investigated.", type: "success" },
    generated: { text: "Demo dataset regenerated.", type: "success" },
    error: { text: "Something went wrong.", type: "error" },
  };

  function toast(message, kind) {
    var stack = document.getElementById("toast-stack");
    if (!stack) return;
    var el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    var msg = document.createElement("div");
    msg.className = "toast-msg";
    msg.textContent = message;
    el.appendChild(msg);
    stack.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      el.style.transition = "opacity .25s ease";
      setTimeout(function () { el.remove(); }, 260);
    }, 4200);
  }

  function spinner() {
    var s = document.createElement("span");
    s.className = "spinner";
    return s;
  }

  function setLoading(button, loading) {
    if (loading) {
      var label = button.getAttribute("data-loading-label") || "Working…";
      button.dataset.originalText = button.textContent.trim();
      button.classList.add("is-loading");
      button.disabled = true;
      button.prepend(spinner());
      button.appendChild(document.createTextNode(" " + label));
    } else {
      button.classList.remove("is-loading");
      button.disabled = false;
      while (button.firstChild) button.removeChild(button.firstChild);
      if (button.dataset.originalText) button.appendChild(document.createTextNode(button.dataset.originalText));
    }
  }

  function handleFlash() {
    var f = new URLSearchParams(window.location.search).get("flash");
    if (!f || !FLASH_MESSAGES[f]) return;
    var m = FLASH_MESSAGES[f];
    toast(m.text, m.type);
    var url = new URL(window.location.href);
    url.searchParams.delete("flash");
    history.replaceState(null, "", url.toString());
  }

  function bindForms() {
    document.querySelectorAll("form[data-remote]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        var buttons = form.querySelectorAll("button");
        var button = buttons[0] || null;

        var confirmMsg = form.getAttribute("data-confirm") || (button ? button.getAttribute("data-confirm") : null);
        if (confirmMsg && !window.confirm(confirmMsg)) {
          e.preventDefault();
          return;
        }
        e.preventDefault();
        if (button) setLoading(button, true);

        fetch(form.action, { method: "POST", body: new FormData(form) })
          .then(function (r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json().catch(function () { return {}; });
          })
          .then(function (data) {
            if (data && data.summary) {
              toast("Verdict: " + data.disposition + " (" + Math.round(data.confidence * 100) + "%)", "success");
            } else {
              toast("Done.", "success");
            }
            if (form.getAttribute("data-reload") !== null) {
              setTimeout(function () { window.location.reload(); }, 600);
            }
          })
          .catch(function () {
            toast("Request failed. Check the server log.", "error");
            if (button) setLoading(button, false);
          });
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    handleFlash();
    bindForms();
  });
})();