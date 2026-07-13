"""Shared Jinja2 templates instance for the console."""
import os

from fastapi.templating import Jinja2Templates

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = os.path.join(_HERE, "static")

templates = Jinja2Templates(directory=os.path.join(_HERE, "templates"))


def _asset_version() -> str:
    """Fingerprint the static assets by their newest mtime.

    Appended to the CSS/JS URLs so a deploy that changes them changes the URL too.
    Without this the browser keeps a cached stylesheet against freshly-rendered
    markup — the page renders unstyled and looks broken. Computed once at import:
    the files ship in the image and never change while the process is alive."""
    stamp = 0.0
    for name in ("style.css", "console.js"):
        path = os.path.join(_STATIC, name)
        if os.path.exists(path):
            stamp = max(stamp, os.path.getmtime(path))
    return str(int(stamp))


templates.env.globals["asset_version"] = _asset_version()
