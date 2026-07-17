"""Shared Jinja2 templates instance for the console.

Jinja2 is a template engine: HTML files with placeholders like ``{{ name }}`` and
mini-logic like loops/ifs. At request time we "render" a template with some data
and get finished HTML back. Rather than each route creating its own engine, we
build one shared engine (the "environment") here and import it everywhere, so all
pages share the same settings, helper values ("globals"), and helper functions
("filters"). This file also wires up two such helpers used across the templates.
"""
import os  # needed to resolve filesystem paths relative to this file

# FastAPI's thin wrapper around Jinja2 that renders TemplateResponse objects
from fastapi.templating import Jinja2Templates

# Absolute directory this file lives in — used as the anchor for all other paths
# so templates/static resolve correctly regardless of the process's cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
# Directory containing the console's static assets (css/js)
_STATIC = os.path.join(_HERE, "static")

# Single shared Jinja2Templates instance pointed at the console's templates dir;
# imported by every route module so they all render through the same environment
templates = Jinja2Templates(directory=os.path.join(_HERE, "templates"))


def _asset_version() -> str:
    """Fingerprint the static assets by their newest mtime.

    This is a "cache-busting" trick. Browsers cache CSS/JS by URL, so if we always
    served ``style.css`` the browser might keep an old copy after a deploy. By
    tacking a version number (derived from the file's last-modified time, "mtime")
    onto the URL, any change to the file changes the URL, forcing a fresh download.

    Appended to the CSS/JS URLs so a deploy that changes them changes the URL too.
    Without this the browser keeps a cached stylesheet against freshly-rendered
    markup — the page renders unstyled and looks broken. Computed once at import:
    the files ship in the image and never change while the process is alive."""
    stamp = 0.0  # running max mtime; 0.0 if neither asset file is found
    # Check both tracked static assets so the version bumps if either changes
    for name in ("style.css", "console.js"):
        path = os.path.join(_STATIC, name)  # full path to this asset
        if os.path.exists(path):  # skip files that don't exist (e.g. no JS yet)
            stamp = max(stamp, os.path.getmtime(path))  # keep the newest mtime seen
    return str(int(stamp))  # truncate to whole seconds and stringify for URL use


# A Jinja "global" is a value made available to every template automatically.
# Registering it here means any template can write {{ asset_version }} directly.
# Compute the version once at import time and expose it to all Jinja templates
# as a global, so `{{ asset_version }}` can be used in template URLs
templates.env.globals["asset_version"] = _asset_version()


# Plain-English labels for the internal triage-action codes, so the UI never shows
# raw enum strings like "create_flagged". The stored values are unchanged (filters,
# routes and the DB still use the codes) — this only affects how they read on screen.
_ACTION_LABELS = {
    "create_flagged": "Flagged urgent",
    "create_open": "Needs review",
    "auto_close": "Closed automatically",
    "suppress_duplicate": "Merged duplicate",
}


def action_label(code) -> str:
    """Human-friendly name for a triage-action code; unknown/empty codes pass through."""
    if not code:
        return "—"
    return _ACTION_LABELS.get(code, code)


# A Jinja "filter" is a function you can pipe a value through inside a template
# using the | syntax. Registering action_label here lets templates convert a raw
# code to its friendly label right where they display it.
# Expose as a Jinja filter: {{ inv.triage_action | action_label }}
templates.env.filters["action_label"] = action_label
