/* RAM v2 analyst console — vanilla JS enhancements.
 * No framework. Progressive: everything still works if this file fails to load.
 *  - chat: auto-scroll to newest, a "thinking" indicator while the agent works,
 *    Enter-to-send (Shift+Enter = newline)
 *  - copy-to-clipboard on case ids / IPs / hashes ([data-copy])
 *  - toast confirmations (promotes server-rendered .flash + copy feedback)
 */
(function () {
  "use strict";

  function toast(message, kind) {
    var c = document.getElementById("toast-container");
    if (!c) {
      c = document.createElement("div");
      c.id = "toast-container";
      c.setAttribute("aria-live", "polite");
      document.body.appendChild(c);
    }
    var t = document.createElement("div");
    t.className = "toast " + (kind === "bad" ? "bad" : "ok");
    t.textContent = message;
    c.appendChild(t);
    requestAnimationFrame(function () { t.classList.add("show"); });
    setTimeout(function () {
      t.classList.remove("show");
      setTimeout(function () { t.remove(); }, 300);
    }, 4000);
  }
  window.ramToast = toast;

  function chatLog() { return document.getElementById("chat-log"); }
  function scrollChat() {
    var l = chatLog();
    if (l) l.scrollTop = l.scrollHeight;
  }

  function addThinking() {
    var log = chatLog();
    if (!log || document.getElementById("chat-thinking")) return;
    var el = document.createElement("div");
    el.className = "chat-msg chat-agent chat-thinking";
    el.id = "chat-thinking";
    var meta = document.createElement("div");
    meta.className = "chat-meta";
    var who = document.createElement("strong");
    who.textContent = "Assistant";
    meta.appendChild(who);
    var body = document.createElement("div");
    body.className = "chat-body";
    var dots = document.createElement("span");
    dots.className = "dots";
    dots.appendChild(document.createElement("span"));
    dots.appendChild(document.createElement("span"));
    dots.appendChild(document.createElement("span"));
    body.appendChild(dots);
    body.appendChild(document.createTextNode(" thinking…"));
    el.appendChild(meta);
    el.appendChild(body);
    log.appendChild(el);
    scrollChat();
  }
  function removeThinking() {
    var el = document.getElementById("chat-thinking");
    if (el) el.remove();
  }

  function isChatForm(el) {
    return el && el.classList && el.classList.contains("chat-form");
  }

  document.body.addEventListener("htmx:beforeRequest", function (e) {
    if (isChatForm(e.target)) addThinking();
  });
  document.body.addEventListener("htmx:afterRequest", function (e) {
    if (isChatForm(e.target)) removeThinking();
  });
  document.body.addEventListener("htmx:afterSwap", function (e) {
    if (e.target && e.target.id === "chat-log") scrollChat();
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" || e.shiftKey) return;
    var ta = e.target;
    if (!ta || ta.tagName !== "TEXTAREA") return;
    var form = ta.closest(".chat-form");
    if (!form) return;
    e.preventDefault();
    if (window.htmx) window.htmx.trigger(form, "submit");
    else form.requestSubmit();
  });

  document.addEventListener("click", function (e) {
    var chip = e.target.closest ? e.target.closest("[data-fill-prompt]") : null;
    if (!chip) return;
    var ta = document.querySelector(".chat-form textarea");
    if (!ta) return;
    ta.value = chip.getAttribute("data-fill-prompt") || "";
    ta.focus();
    toast("Prompt prepared");
  });

  document.addEventListener("click", function (e) {
    var el = e.target.closest ? e.target.closest("[data-copy]") : null;
    if (!el) return;
    var text = el.getAttribute("data-copy") || el.textContent.trim();
    var done = function () { toast("Copied: " + text); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { done(); });
    } else {
      done();
    }
  });

  /* --- global assistant dock ---------------------------------------------- */
  var dockLoaded = false;
  function dock() { return document.getElementById("assistant-dock"); }
  function openDock() {
    var d = dock();
    if (!d) return;
    d.classList.add("open");
    d.setAttribute("aria-hidden", "false");
    var bd = document.getElementById("assistant-backdrop");
    if (bd) bd.hidden = false;
    var tog = document.getElementById("assistant-toggle");
    if (tog) tog.setAttribute("aria-expanded", "true");
    // lazy-load the thread on first open (htmx custom trigger on #chat-log)
    if (!dockLoaded) {
      dockLoaded = true;
      var log = chatLog();
      if (log && window.htmx) window.htmx.trigger(log, "dockopen");
    }
    var ta = d.querySelector(".chat-form textarea");
    if (ta) ta.focus();
    scrollChat();
  }
  function closeDock() {
    var d = dock();
    if (!d) return;
    d.classList.remove("open");
    d.setAttribute("aria-hidden", "true");
    var bd = document.getElementById("assistant-backdrop");
    if (bd) bd.hidden = true;
    var tog = document.getElementById("assistant-toggle");
    if (tog) tog.setAttribute("aria-expanded", "false");
  }
  function dockOpen() { return dock() && dock().classList.contains("open"); }

  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest("#assistant-toggle, [data-open-assistant]")) {
      e.preventDefault();
      dockOpen() ? closeDock() : openDock();
      return;
    }
    if (e.target.closest && e.target.closest("#assistant-close, #assistant-backdrop")) {
      closeDock();
    }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && dockOpen()) closeDock();
  });

  /* --- queue row delete: arm, then confirm --------------------------------- */
  // Deleting an investigation is irreversible, so it takes two deliberate clicks.
  // The confirmation happens in the row itself (a native confirm() dialog throws
  // the analyst out of the interface to ask one question). Only one row can be
  // armed at a time; Escape or a click elsewhere stands it down.
  function disarmAll(except) {
    document.querySelectorAll(".row-delete.armed").forEach(function (f) {
      if (f === except) return;
      f.classList.remove("armed");
      var c = f.querySelector(".arm-confirm");
      if (c) c.hidden = true;
      var r = f.closest("tr");
      if (r) r.classList.remove("row-arming");
    });
  }
  function armDelete(form) {
    disarmAll(form);
    form.classList.add("armed");
    var confirm = form.querySelector(".arm-confirm");
    if (confirm) confirm.hidden = false;
    var row = form.closest("tr");
    if (row) row.classList.add("row-arming");
    var confirmBtn = form.querySelector(".btn-confirm-delete");
    if (confirmBtn) confirmBtn.focus();
  }

  document.addEventListener("click", function (e) {
    var arm = e.target.closest ? e.target.closest("[data-arm-delete]") : null;
    if (arm) {
      e.preventDefault();
      e.stopPropagation();
      armDelete(arm.closest(".row-delete"));
      return;
    }
    var cancel = e.target.closest ? e.target.closest("[data-cancel-delete]") : null;
    if (cancel) {
      e.preventDefault();
      e.stopPropagation();
      disarmAll();
      return;
    }
    if (!e.target.closest || e.target.closest(".row-delete.armed")) return;
    // A click anywhere else stands the armed row down. If that click landed on the
    // armed row itself, it must ONLY stand it down — not also open the row — so we
    // stop the click-through handler (registered after this one) from seeing it.
    var armedRow = document.querySelector("tr.row-arming");
    disarmAll();
    if (armedRow && armedRow.contains(e.target)) e.stopImmediatePropagation();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") disarmAll();
  });

  /* --- bulk selection (queue + memory) ------------------------------------ */
  // The bulk bar only exists once a row is selected — an empty toolbar sitting
  // above the table is noise. Same two-step arm/confirm as the single-row delete,
  // and the confirm button restates the count so nobody destroys 25 rows thinking
  // they picked 2.
  function bulkBar() { return document.querySelector("[data-bulk-bar]"); }
  function selected() {
    return Array.prototype.slice.call(document.querySelectorAll("[data-row-select]:checked"));
  }
  function disarmBulk() {
    var bar = bulkBar();
    if (!bar) return;
    bar.classList.remove("armed");
    var c = bar.querySelector(".bulk-confirm");
    if (c) c.hidden = true;
    var arm = bar.querySelector("[data-bulk-arm]");
    if (arm) arm.hidden = false;
  }
  function syncBulk() {
    var bar = bulkBar();
    if (!bar) return;
    var n = selected().length;
    bar.querySelectorAll("[data-bulk-count]").forEach(function (el) { el.textContent = n; });
    bar.hidden = n === 0;
    if (n === 0) disarmBulk();
    var all = document.querySelector("[data-select-all]");
    var boxes = document.querySelectorAll("[data-row-select]");
    if (all) {
      all.checked = n > 0 && n === boxes.length;
      all.indeterminate = n > 0 && n < boxes.length;
    }
  }

  document.addEventListener("change", function (e) {
    if (e.target.matches && e.target.matches("[data-select-all]")) {
      var on = e.target.checked;
      document.querySelectorAll("[data-row-select]").forEach(function (b) { b.checked = on; });
      syncBulk();
      return;
    }
    if (e.target.matches && e.target.matches("[data-row-select]")) syncBulk();
  });

  document.addEventListener("click", function (e) {
    if (!e.target.closest) return;
    if (e.target.closest("[data-bulk-arm]")) {
      var bar = bulkBar();
      bar.classList.add("armed");
      bar.querySelector(".bulk-confirm").hidden = false;
      e.target.closest("[data-bulk-arm]").hidden = true;
      var go = bar.querySelector("[data-bulk-submit]");
      if (go) go.focus();
      return;
    }
    if (e.target.closest("[data-bulk-disarm]")) { disarmBulk(); return; }
    if (e.target.closest("[data-bulk-clear]")) {
      document.querySelectorAll("[data-row-select]").forEach(function (b) { b.checked = false; });
      syncBulk();
      return;
    }
  });

  /* --- queue row click-through -------------------------------------------- */
  // Whole row opens the investigation, except when a link/button/copyable cell
  // was the actual click target (those keep their own behavior), or when the row
  // is armed for deletion (a stray click must not navigate away mid-decision).
  document.addEventListener("click", function (e) {
    var row = e.target.closest ? e.target.closest("tr[data-href]") : null;
    if (!row) return;
    if (row.classList.contains("row-arming")) return;
    if (e.target.closest("a, button, input, label, form, [data-copy], .col-select")) return;
    window.location.href = row.getAttribute("data-href");
  });

  document.addEventListener("DOMContentLoaded", function () {
    scrollChat();
    syncBulk();  // a back/forward restore can bring checked boxes with it
    document.querySelectorAll(".flash").forEach(function (f) {
      toast(f.textContent.trim(), f.classList.contains("bad") ? "bad" : "ok");
      f.remove();
    });
  });
})();
