/* RAM v2 analyst console — vanilla JS enhancements.
 * No framework. Progressive: everything still works if this file fails to load.
 *  - chat: auto-scroll to newest, a "thinking" indicator while the agent works,
 *    Enter-to-send (Shift+Enter = newline)
 *  - copy-to-clipboard on case ids / IPs / hashes ([data-copy])
 *  - toast confirmations (promotes server-rendered .flash + copy feedback)
 */
// Wrap everything in an IIFE so none of these helpers/vars leak onto `window`
// (except the one explicit export below), and so this file can be re-included
// safely without redeclaration errors.
(function () {
  // Strict mode: catches silent bugs (accidental globals, etc.) in this closure.
  "use strict";

  // Show a small transient notification. `kind` selects the ok/bad color treatment.
  function toast(message, kind) {
    // Reuse a single toast container across calls; create it lazily on first use.
    var c = document.getElementById("toast-container");
    if (!c) {
      // Container doesn't exist yet — build it once and attach to the page.
      c = document.createElement("div");
      c.id = "toast-container";
      // Announce new toasts to screen readers without stealing focus.
      c.setAttribute("aria-live", "polite");
      document.body.appendChild(c);
    }
    // Build the individual toast element for this message.
    var t = document.createElement("div");
    // "bad" gets the error styling; anything else (including undefined) defaults to "ok".
    t.className = "toast " + (kind === "bad" ? "bad" : "ok");
    t.textContent = message;
    c.appendChild(t);
    // Add the "show" class on the next animation frame so the CSS transition
    // (opacity/transform) actually animates in, instead of snapping to visible.
    requestAnimationFrame(function () { t.classList.add("show"); });
    // Auto-dismiss after 4s: fade out, then remove from the DOM once the
    // fade transition (300ms) has had time to finish.
    setTimeout(function () {
      t.classList.remove("show");
      setTimeout(function () { t.remove(); }, 300);
    }, 4000);
  }
  // Expose toast() globally so server-rendered inline scripts / other code can call it.
  window.ramToast = toast;

  // Shorthand accessor for the chat transcript container element.
  function chatLog() { return document.getElementById("chat-log"); }
  // Pin the chat scroll position to the bottom so new messages are visible.
  function scrollChat() {
    var l = chatLog();
    if (l) l.scrollTop = l.scrollHeight;
  }

  // Insert a "thinking…" placeholder bubble while waiting on the agent's htmx response.
  function addThinking() {
    var log = chatLog();
    // Bail if there's no chat log on this page, or a thinking indicator is already showing
    // (avoids stacking duplicates if beforeRequest somehow fires twice).
    if (!log || document.getElementById("chat-thinking")) return;
    // Build a fake chat-agent message bubble to hold the indicator.
    var el = document.createElement("div");
    el.className = "chat-msg chat-agent chat-thinking";
    el.id = "chat-thinking";
    // Header row showing who is "speaking" (mirrors real chat message markup).
    var meta = document.createElement("div");
    meta.className = "chat-meta";
    var who = document.createElement("strong");
    who.textContent = "Assistant";
    meta.appendChild(who);
    // Body row holds the animated dots + label.
    var body = document.createElement("div");
    body.className = "chat-body";
    // Three-dot loading animation, styled/animated purely via CSS.
    var dots = document.createElement("span");
    dots.className = "dots";
    dots.appendChild(document.createElement("span"));
    dots.appendChild(document.createElement("span"));
    dots.appendChild(document.createElement("span"));
    body.appendChild(dots);
    // Trailing text next to the dots.
    body.appendChild(document.createTextNode(" thinking…"));
    el.appendChild(meta);
    el.appendChild(body);
    // Append to the end of the transcript and scroll it into view.
    log.appendChild(el);
    scrollChat();
  }
  // Remove the thinking indicator once the request settles (success or failure).
  function removeThinking() {
    var el = document.getElementById("chat-thinking");
    if (el) el.remove();
  }

  // True if the given element is the chat message form (used to filter htmx events
  // so we only react to the chat form's requests, not every htmx-driven form on the page).
  function isChatForm(el) {
    return el && el.classList && el.classList.contains("chat-form");
  }

  // htmx lifecycle hook: fires right before the chat form's request is sent.
  document.body.addEventListener("htmx:beforeRequest", function (e) {
    if (isChatForm(e.target)) addThinking();
  });
  // htmx lifecycle hook: fires after the chat form's request completes (success or error).
  document.body.addEventListener("htmx:afterRequest", function (e) {
    if (isChatForm(e.target)) removeThinking();
  });
  // htmx lifecycle hook: fires after htmx swaps new content into the DOM.
  document.body.addEventListener("htmx:afterSwap", function (e) {
    // Only auto-scroll when the swap targeted the chat log itself (a new message arrived).
    if (e.target && e.target.id === "chat-log") scrollChat();
  });

  // Global keydown listener: implements Enter-to-send / Shift+Enter-for-newline in the chat textarea.
  document.addEventListener("keydown", function (e) {
    // Ignore anything but a plain Enter; Shift+Enter should insert a newline as usual.
    if (e.key !== "Enter" || e.shiftKey) return;
    var ta = e.target;
    // Only intercept Enter when it's pressed inside a textarea (not arbitrary inputs).
    if (!ta || ta.tagName !== "TEXTAREA") return;
    // Find the enclosing chat form; if this textarea isn't part of one, do nothing special.
    var form = ta.closest(".chat-form");
    if (!form) return;
    // Stop the default newline-insertion behavior of Enter in a textarea.
    e.preventDefault();
    // Prefer triggering htmx's own submit handling (so its request/response hooks run);
    // fall back to the native form submit if htmx isn't loaded.
    if (window.htmx) window.htmx.trigger(form, "submit");
    else form.requestSubmit();
  });

  // Global click listener: clicking a suggested-prompt "chip" fills the chat textarea with it.
  document.addEventListener("click", function (e) {
    // closest() may be undefined on some synthetic targets, so guard before calling it.
    var chip = e.target.closest ? e.target.closest("[data-fill-prompt]") : null;
    if (!chip) return;
    // Find the chat textarea to populate; nothing to do if this page has no chat form.
    var ta = document.querySelector(".chat-form textarea");
    if (!ta) return;
    // Pull the canned prompt text from the chip's data attribute.
    ta.value = chip.getAttribute("data-fill-prompt") || "";
    // Move focus into the textarea so the analyst can edit/send immediately.
    ta.focus();
    // Small confirmation so the analyst knows the click did something.
    toast("Prompt prepared");
  });

  // Global click listener: implements copy-to-clipboard on any [data-copy] element
  // (case ids, IPs, hashes, etc.).
  document.addEventListener("click", function (e) {
    var el = e.target.closest ? e.target.closest("[data-copy]") : null;
    if (!el) return;
    // Prefer an explicit data-copy value; otherwise fall back to the element's visible text.
    var text = el.getAttribute("data-copy") || el.textContent.trim();
    // Toast callback fires regardless of clipboard success/failure — the copy still
    // effectively "worked" from the analyst's perspective in older/permission-denied browsers.
    var done = function () { toast("Copied: " + text); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      // Modern async Clipboard API; show the toast whether it resolves or rejects.
      navigator.clipboard.writeText(text).then(done, function () { done(); });
    } else {
      // No Clipboard API available — just show the toast (best-effort UX, no real copy).
      done();
    }
  });

  /* --- global assistant dock ---------------------------------------------- */
  // Tracks whether the chat thread inside the dock has been lazy-loaded yet,
  // so we only trigger the htmx load once per page load.
  var dockLoaded = false;
  // Shorthand accessor for the slide-in assistant dock element.
  function dock() { return document.getElementById("assistant-dock"); }
  // Open (slide in) the assistant dock and wire up its accessibility state.
  function openDock() {
    var d = dock();
    if (!d) return;
    // CSS transition/visibility is driven by the "open" class.
    d.classList.add("open");
    // Tell assistive tech the panel is now visible/interactive.
    d.setAttribute("aria-hidden", "false");
    var bd = document.getElementById("assistant-backdrop");
    // Reveal the dimming backdrop behind the dock, if present on this page.
    if (bd) bd.hidden = false;
    var tog = document.getElementById("assistant-toggle");
    // Reflect open state on the toggle button for screen readers / styling.
    if (tog) tog.setAttribute("aria-expanded", "true");
    // lazy-load the thread on first open (htmx custom trigger on #chat-log)
    if (!dockLoaded) {
      dockLoaded = true;
      var log = chatLog();
      // Fire a custom htmx trigger so the server-rendered chat history loads
      // only when the analyst actually opens the dock, not on every page load.
      if (log && window.htmx) window.htmx.trigger(log, "dockopen");
    }
    // Move focus into the message box so the analyst can start typing immediately.
    var ta = d.querySelector(".chat-form textarea");
    if (ta) ta.focus();
    // Ensure the transcript is scrolled to the latest message when it opens.
    scrollChat();
  }
  // Close (slide out) the assistant dock and reverse the accessibility state.
  function closeDock() {
    var d = dock();
    if (!d) return;
    d.classList.remove("open");
    d.setAttribute("aria-hidden", "true");
    var bd = document.getElementById("assistant-backdrop");
    // Hide the backdrop again now that the dock is closed.
    if (bd) bd.hidden = true;
    var tog = document.getElementById("assistant-toggle");
    if (tog) tog.setAttribute("aria-expanded", "false");
  }
  // Convenience predicate: is the dock currently open?
  function dockOpen() { return dock() && dock().classList.contains("open"); }

  // Global click listener: toggles the dock open/closed, and handles its close controls.
  document.addEventListener("click", function (e) {
    // Clicking the header toggle button (or any element opting in via data-open-assistant)
    // flips the dock's open state.
    if (e.target.closest && e.target.closest("#assistant-toggle, [data-open-assistant]")) {
      // Prevent default in case the toggle is an <a> or submit button.
      e.preventDefault();
      dockOpen() ? closeDock() : openDock();
      return;
    }
    // Clicking the explicit close button or the dimmed backdrop always closes the dock.
    if (e.target.closest && e.target.closest("#assistant-close, #assistant-backdrop")) {
      closeDock();
    }
  });
  // Global keydown listener: Escape closes the dock if it's open (standard modal convention).
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && dockOpen()) closeDock();
  });

  /* --- queue row delete: arm, then confirm --------------------------------- */
  // Deleting an investigation is irreversible, so it takes two deliberate clicks.
  // The confirmation happens in the row itself (a native confirm() dialog throws
  // the analyst out of the interface to ask one question). Only one row can be
  // armed at a time; Escape or a click elsewhere stands it down.
  // Disarm every armed delete-row form except the one passed in (if any),
  // so at most one row is ever "armed" (awaiting confirmation) at a time.
  function disarmAll(except) {
    document.querySelectorAll(".row-delete.armed").forEach(function (f) {
      // Skip the form we're intentionally keeping armed (e.g. the one just armed).
      if (f === except) return;
      // Drop the armed state so the CSS reverts to showing the trash icon, not confirm buttons.
      f.classList.remove("armed");
      var c = f.querySelector(".arm-confirm");
      // Re-hide the confirm/cancel buttons for this row.
      if (c) c.hidden = true;
      var r = f.closest("tr");
      // Remove the visual "arming" tint from the enclosing table row.
      if (r) r.classList.remove("row-arming");
    });
  }
  // Arm a specific delete form: shows its confirm/cancel controls and highlights the row.
  function armDelete(form) {
    // Stand down any other armed row first — only one confirmation should be visible.
    disarmAll(form);
    form.classList.add("armed");
    var confirm = form.querySelector(".arm-confirm");
    // Reveal the "confirm delete" / "cancel" button pair.
    if (confirm) confirm.hidden = false;
    var row = form.closest("tr");
    // Tint the whole row so it's visually obvious a destructive action is pending.
    if (row) row.classList.add("row-arming");
    var confirmBtn = form.querySelector(".btn-confirm-delete");
    // Move focus to the confirm button so a keyboard user can immediately confirm or tab away.
    if (confirmBtn) confirmBtn.focus();
  }

  // Global click listener: handles arming and canceling the per-row delete confirmation.
  document.addEventListener("click", function (e) {
    var arm = e.target.closest ? e.target.closest("[data-arm-delete]") : null;
    if (arm) {
      // Prevent the trash button from submitting/navigating; we're just arming, not deleting yet.
      e.preventDefault();
      // Stop this click from also being seen by the "click elsewhere disarms" handler below.
      e.stopPropagation();
      armDelete(arm.closest(".row-delete"));
      return;
    }
    var cancel = e.target.closest ? e.target.closest("[data-cancel-delete]") : null;
    if (cancel) {
      e.preventDefault();
      e.stopPropagation();
      // Explicit "cancel" always stands every armed row down.
      disarmAll();
      return;
    }
    // If the click can't be inspected, or it landed inside a currently-armed row
    // (i.e. on the confirm/cancel buttons themselves), don't fall through to disarm logic.
    if (!e.target.closest || e.target.closest(".row-delete.armed")) return;
    // A click anywhere else stands the armed row down. If that click landed on the
    // armed row itself, it must ONLY stand it down — not also open the row — so we
    // stop the click-through handler (registered after this one) from seeing it.
    var armedRow = document.querySelector("tr.row-arming");
    disarmAll();
    // Suppress the row-click-through handler (added later, so it would otherwise
    // still run and navigate) when the disarming click was inside the armed row.
    if (armedRow && armedRow.contains(e.target)) e.stopImmediatePropagation();
  });
  // Global keydown listener: Escape also stands down any armed delete row.
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") disarmAll();
  });

  /* --- bulk selection (queue + memory) ------------------------------------ */
  // The bulk bar only exists once a row is selected — an empty toolbar sitting
  // above the table is noise. Same two-step arm/confirm as the single-row delete,
  // and the confirm button restates the count so nobody destroys 25 rows thinking
  // they picked 2.
  // Shorthand accessor for the bulk action toolbar.
  function bulkBar() { return document.querySelector("[data-bulk-bar]"); }
  // Return the currently checked row-selection checkboxes as a real array
  // (querySelectorAll returns a NodeList, so we need Array.prototype.slice to get .map/.filter etc.).
  function selected() {
    return Array.prototype.slice.call(document.querySelectorAll("[data-row-select]:checked"));
  }
  // Reset the bulk bar out of its "armed" (confirming) state, e.g. after a bulk action
  // completes or the selection changes.
  function disarmBulk() {
    var bar = bulkBar();
    if (!bar) return;
    bar.classList.remove("armed");
    var c = bar.querySelector(".bulk-confirm");
    // Hide the confirm controls again.
    if (c) c.hidden = true;
    var arm = bar.querySelector("[data-bulk-arm]");
    // Restore the initial "delete selected" button.
    if (arm) arm.hidden = false;
  }
  // Recompute and reflect the current selection state: count, bar visibility,
  // and the header "select all" checkbox's checked/indeterminate state.
  function syncBulk() {
    var bar = bulkBar();
    if (!bar) return;
    var n = selected().length;
    // Update every element that displays the selected count (there may be more than one).
    bar.querySelectorAll("[data-bulk-count]").forEach(function (el) { el.textContent = n; });
    // Hide the whole bar when nothing is selected — no noise above an inactive table.
    bar.hidden = n === 0;
    // If selection dropped to zero, also cancel any pending bulk confirmation.
    if (n === 0) disarmBulk();
    var all = document.querySelector("[data-select-all]");
    var boxes = document.querySelectorAll("[data-row-select]");
    if (all) {
      // "Select all" reads as checked only when every row is selected.
      all.checked = n > 0 && n === boxes.length;
      // Indeterminate (dash) state communicates a partial selection.
      all.indeterminate = n > 0 && n < boxes.length;
    }
  }

  // Global change listener: keeps selection state and the bulk bar in sync
  // whenever a checkbox (row or "select all") is toggled.
  document.addEventListener("change", function (e) {
    if (e.target.matches && e.target.matches("[data-select-all]")) {
      // Propagate the header checkbox's new state to every row checkbox.
      var on = e.target.checked;
      document.querySelectorAll("[data-row-select]").forEach(function (b) { b.checked = on; });
      syncBulk();
      return;
    }
    // A single row's checkbox changed — just recompute the summary state.
    if (e.target.matches && e.target.matches("[data-row-select]")) syncBulk();
  });

  // Global click listener: drives the bulk bar's arm / disarm / clear-selection controls.
  document.addEventListener("click", function (e) {
    if (!e.target.closest) return;
    if (e.target.closest("[data-bulk-arm]")) {
      // "Delete selected" was clicked — arm the bar to show the confirm step.
      var bar = bulkBar();
      bar.classList.add("armed");
      bar.querySelector(".bulk-confirm").hidden = false;
      // Hide the original arm button now that confirm controls are showing.
      e.target.closest("[data-bulk-arm]").hidden = true;
      var go = bar.querySelector("[data-bulk-submit]");
      // Focus the actual submit button so a keyboard user can confirm right away.
      if (go) go.focus();
      return;
    }
    // "Cancel"/back-out of the bulk confirm step.
    if (e.target.closest("[data-bulk-disarm]")) { disarmBulk(); return; }
    if (e.target.closest("[data-bulk-clear]")) {
      // "Clear selection" — uncheck every row and refresh the bar (which will hide itself).
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
    // Only rows carrying a data-href are navigable this way.
    var row = e.target.closest ? e.target.closest("tr[data-href]") : null;
    if (!row) return;
    // Never navigate away from a row that's mid-delete-confirmation.
    if (row.classList.contains("row-arming")) return;
    // If the click actually hit an interactive/copyable element inside the row,
    // let that element's own handler run instead of also navigating the row.
    if (e.target.closest("a, button, input, label, form, [data-copy], .col-select")) return;
    // Otherwise, treat the click as "open this investigation".
    window.location.href = row.getAttribute("data-href");
  });

  /* --- correlated-cases carousel ------------------------------------------ */
  // Prev/next arrows page the horizontal track by roughly one card width. Arrow
  // disabled-state reflects whether there's more to scroll in that direction.
  function carouselViewport(btn) {
    // Both the carousel and its arrows live under the same overview section;
    // find the scroll viewport nearest the clicked control.
    var head = btn.closest(".corr-head");
    var wrap = head ? head.parentElement.querySelector("[data-carousel]") : null;
    return wrap;
  }
  function cardStep(track) {
    // Scroll by one card + gap; fall back to 320px if the track is empty.
    var card = track.querySelector(".corr-card");
    if (!card) return 320;
    var gap = parseInt(getComputedStyle(track).columnGap || getComputedStyle(track).gap || "12", 10) || 12;
    return card.getBoundingClientRect().width + gap;
  }
  function syncCarousel(wrap) {
    if (!wrap) return;
    var head = wrap.parentElement.querySelector(".corr-nav");
    if (!head) return;
    var prev = head.querySelector("[data-carousel-prev]");
    var next = head.querySelector("[data-carousel-next]");
    // 2px slack absorbs sub-pixel rounding at the extremes.
    var atStart = wrap.scrollLeft <= 2;
    var atEnd = wrap.scrollLeft + wrap.clientWidth >= wrap.scrollWidth - 2;
    if (prev) prev.disabled = atStart;
    if (next) next.disabled = atEnd;
  }
  document.addEventListener("click", function (e) {
    if (!e.target.closest) return;
    var prev = e.target.closest("[data-carousel-prev]");
    var next = e.target.closest("[data-carousel-next]");
    if (!prev && !next) return;
    var wrap = carouselViewport(prev || next);
    if (!wrap) return;
    var track = wrap.querySelector("[data-carousel-track]");
    var step = cardStep(track);
    wrap.scrollBy({ left: next ? step : -step, behavior: "smooth" });
    // Re-check arrow state after the smooth scroll settles.
    setTimeout(function () { syncCarousel(wrap); }, 350);
  });
  // Keep arrow state in sync if the user scrolls the track directly (trackpad/touch).
  document.addEventListener("scroll", function (e) {
    if (e.target.matches && e.target.matches("[data-carousel]")) syncCarousel(e.target);
  }, true);

  // Run once the initial HTML document has been fully parsed.
  document.addEventListener("DOMContentLoaded", function () {
    // Initialize each carousel's arrow enabled/disabled state.
    document.querySelectorAll("[data-carousel]").forEach(syncCarousel);
    // Jump the chat transcript to the bottom on load.
    scrollChat();
    syncBulk();  // a back/forward restore can bring checked boxes with it
    // Promote any server-rendered flash messages into toasts, then remove the
    // static markup so it doesn't also sit visible in the page body.
    document.querySelectorAll(".flash").forEach(function (f) {
      toast(f.textContent.trim(), f.classList.contains("bad") ? "bad" : "ok");
      f.remove();
    });
  });
})();
