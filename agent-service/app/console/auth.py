"""Console authentication: argon2 password hashing + signed-cookie sessions.

Two beginner concepts this file relies on:

* Password hashing (argon2): we never store the actual password. We run it
  through a one-way function that turns it into a scrambled "hash". You can
  check a login by hashing the typed password and comparing, but you cannot
  reverse the hash back into the password. So even if the database leaks, the
  real passwords are not exposed. argon2 is a modern, deliberately slow +
  memory-hungry algorithm, which makes brute-force guessing expensive.
* Session cookie: after you log in, the server hands the browser a small signed
  cookie holding your identity. The browser sends it back on every request, so
  the server knows who you are without asking you to log in again each click.
  "Signed" means the server can detect if the cookie was tampered with.

Human console actions use the logged-in analyst identity (session cookie), never
the Phase 2 shared operator token (which stays for machine-to-machine only).
"""
import logging  # standard logging for auth events (failed logins, hash errors)
from typing import Optional  # type hint for functions that may return no user

from argon2 import PasswordHasher  # argon2id password hashing (memory-hard, salted)
from argon2.exceptions import VerifyMismatchError  # raised when a password doesn't match its hash
from fastapi import APIRouter, Form, Request  # router + form-field parsing + request/session access
from fastapi.responses import HTMLResponse, RedirectResponse, Response  # response types used below

from . import store  # console data access (user lookup, audit log writes)
from .templating import templates  # shared Jinja2 environment for rendering login page

logger = logging.getLogger(__name__)  # module-scoped logger
# One reusable object that knows how to create and check argon2 hashes.
# It also stores the tuning parameters (memory/time cost) used for hashing.
_ph = PasswordHasher()  # single hasher instance reused for both hashing and verifying

# An APIRouter is a group of related URL routes. We define them here and the main
# app "includes" this router, which keeps auth endpoints in their own file.
# All routes in this module are mounted under /console and tagged for API docs
router = APIRouter(prefix="/console", tags=["console-auth"])


class NeedsLogin(Exception):
    """Raised by require_analyst when there is no valid session."""


def hash_password(password: str) -> str:
    # Turn a plaintext password into an argon2 hash for safe storage.
    # The result is "self-describing": it embeds the algorithm parameters, a
    # random per-password "salt", and the final digest, so verify_password can
    # later re-derive the same hash. The salt means two identical passwords still
    # produce different-looking hashes, defeating precomputed lookup attacks.
    # Produces a self-describing argon2 hash string (params + salt + digest)
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    # Check a typed password against the stored hash. We never "unhash"; instead
    # argon2 re-hashes the input using the salt/params baked into password_hash
    # and compares. Returns True only if they match.
    try:
        # Returns True on match; raises if the password is wrong or hash is malformed
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False  # correct hash format, but password does not match
    except Exception:  # noqa: BLE001 - malformed hash etc.
        # Any other failure (e.g. corrupt/legacy hash) is treated as "not verified",
        # but logged so it's visible rather than silently swallowed
        logger.exception("Password verify error")
        return False


def current_analyst(request: Request) -> Optional[dict]:
    # Read the currently logged-in user out of the session cookie, or None.
    # request.session behaves like a dict; SessionMiddleware (installed on the app)
    # transparently reads the incoming cookie into it and writes any changes back
    # out as a cookie on the response. "Middleware" is code that wraps every
    # request/response to do this kind of cross-cutting work automatically.
    # The session cookie is signed/encrypted by FastAPI's SessionMiddleware, so
    # this dict is trustworthy without re-checking the DB on every request
    username = request.session.get("username")
    if not username:
        return None  # no session -> not logged in
    return {
        "username": username,
        "display_name": request.session.get("display_name") or username,  # fall back to username
        "role": request.session.get("role") or "analyst",  # fall back to least-privileged role
    }


def require_analyst(request: Request) -> dict:
    """Dependency for protected routes. Raises NeedsLogin if unauthenticated.

    In FastAPI a "dependency" is a function a route can declare it needs; FastAPI
    runs it before the route and passes the result in. Here, a protected route
    asks for require_analyst, so anyone not logged in is stopped before the route
    body ever runs.
    """
    analyst = current_analyst(request)
    if analyst is None:
        raise NeedsLogin()  # caught by the app-level exception handler below
    return analyst


# GET /console/login: render the login form (or bounce already-authenticated users away)
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_analyst(request):
        # Already logged in — no reason to show the form again. 303 ("See Other")
        # is the standard redirect that tells the browser to follow up with a GET.
        return RedirectResponse("/console/", status_code=303)
    # error=None on first load; the POST handler re-renders this template with an error
    return templates.TemplateResponse(request, "login.html", {"error": None})


# POST /console/login: verify credentials and establish the session
@router.post("/login", response_class=HTMLResponse)
# Form(...) tells FastAPI to pull these values from the submitted HTML form body
# (the login page's username/password fields). The "..." marks them as required.
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user = store.get_user(username)  # None if the username doesn't exist
    if not user or user["disabled"] or not verify_password(user["password_hash"], password):
        # Same generic error for "no such user", "disabled", and "wrong password" —
        # avoids leaking which case it was to a potential attacker
        logger.warning("Failed login attempt for username=%r", username)
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid credentials"}, status_code=401
        )
    # Credentials check out — write identity/role into the session. Assigning to
    # request.session is what "logs the user in": on the way out, the middleware
    # serialises this into the signed cookie the browser will send back next time.
    # Credentials check out — populate the signed session cookie with identity/role
    request.session.update({
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
    })
    store.write_audit(user["username"], "login", target_type="session")  # audit the login event
    return RedirectResponse("/console/", status_code=303)  # send them to the console home


# GET /console/logout: tear down the session
@router.get("/logout")
def logout(request: Request):
    analyst = current_analyst(request)  # capture who's logging out before clearing the session
    if analyst:
        store.write_audit(analyst["username"], "logout", target_type="session")  # audit the logout
    request.session.clear()  # drop all session data, effectively ending the login
    return RedirectResponse("/console/login", status_code=303)


def needs_login_handler(request: Request, exc: NeedsLogin) -> Response:
    """App-level handler: redirect browsers to login, signal HTMX to redirect.

    Registered on the app so that whenever require_analyst raises NeedsLogin,
    this runs instead of returning an error page — turning "not logged in" into
    a redirect to the login screen. HTMX is the small front-end library the
    console uses to swap page fragments without full reloads.
    """
    if request.headers.get("HX-Request"):
        # HTMX requests can't follow a normal redirect for a full-page navigation;
        # this custom header tells the HTMX client to do a full-page redirect itself
        return Response(status_code=401, headers={"HX-Redirect": "/console/login"})
    # Regular browser navigation: a normal HTTP redirect works fine
    return RedirectResponse("/console/login", status_code=303)
