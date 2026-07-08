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

  document.addEventListener("DOMContentLoaded", function () {
    scrollChat();
    document.querySelectorAll(".flash").forEach(function (f) {
      toast(f.textContent.trim(), f.classList.contains("bad") ? "bad" : "ok");
      f.remove();
    });
  });
})();
