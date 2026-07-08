"""Console authentication: argon2 password hashing + signed-cookie sessions.

Human console actions use the logged-in analyst identity (session cookie), never
the Phase 2 shared operator token (which stays for machine-to-machine only).
"""
import logging
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import store
from .templating import templates

logger = logging.getLogger(__name__)
_ph = PasswordHasher()

router = APIRouter(prefix="/console", tags=["console-auth"])


class NeedsLogin(Exception):
    """Raised by require_analyst when there is no valid session."""


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 - malformed hash etc.
        logger.exception("Password verify error")
        return False


def current_analyst(request: Request) -> Optional[dict]:
    username = request.session.get("username")
    if not username:
        return None
    return {
        "username": username,
        "display_name": request.session.get("display_name") or username,
        "role": request.session.get("role") or "analyst",
    }


def require_analyst(request: Request) -> dict:
    """Dependency for protected routes. Raises NeedsLogin if unauthenticated."""
    analyst = current_analyst(request)
    if analyst is None:
        raise NeedsLogin()
    return analyst


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_analyst(request):
        return RedirectResponse("/console/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user = store.get_user(username)
    if not user or user["disabled"] or not verify_password(user["password_hash"], password):
        logger.warning("Failed login attempt for username=%r", username)
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid credentials"}, status_code=401
        )
    request.session.update({
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
    })
    store.write_audit(user["username"], "login", target_type="session")
    return RedirectResponse("/console/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    analyst = current_analyst(request)
    if analyst:
        store.write_audit(analyst["username"], "logout", target_type="session")
    request.session.clear()
    return RedirectResponse("/console/login", status_code=303)


def needs_login_handler(request: Request, exc: NeedsLogin) -> Response:
    """App-level handler: redirect browsers to login, signal HTMX to redirect."""
    if request.headers.get("HX-Request"):
        return Response(status_code=401, headers={"HX-Redirect": "/console/login"})
    return RedirectResponse("/console/login", status_code=303)
