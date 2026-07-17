"""Interactive CLI to create an analyst console account.

Run inside the service container:

    docker compose exec agent-service python -m app.console.create_user

No credentials are accepted on the command line or via environment — the
password is read interactively with getpass and never echoed, logged, or
stored in plaintext (only its argon2 hash is persisted).
"""
# getpass prompts for a secret at the terminal but hides the keystrokes (no echo),
# so a shoulder-surfer or the shell history can't capture the typed password.
import getpass  # reads the password interactively without echoing it to the terminal
# An "exit code" is the small integer a program returns to the shell: 0 means
# success, anything non-zero means failure. sys.exit hands it back to the OS.
import sys  # used to set the process exit code from main()'s return value

import psycopg  # gives us the specific UniqueViolation error class to catch

from . import store  # console data access layer (user lookup/creation, audit log)
from .auth import hash_password  # argon2 hashing, same as used at login time

# Only these two role values are accepted for a console account
VALID_ROLES = ("analyst", "admin")


# Small helper to ask the user a question at the terminal and return their answer,
# re-asking if a required field is left blank. Keeps main() readable below.
def _prompt(label: str, *, default: str | None = None, required: bool = True) -> str:
    # Show the default value in brackets alongside the prompt, if one was given
    suffix = f" [{default}]" if default else ""
    while True:  # keep re-asking until we get an acceptable value
        value = input(f"{label}{suffix}: ").strip()  # read input, trim whitespace
        if not value and default is not None:
            return default  # empty input falls back to the default, if any
        if value or not required:
            return value  # non-empty input, or empty is fine because it's optional
        print("  (required)")  # nudge the user and loop back to ask again


def main() -> int:  # entry point; return value doubles as the process exit code
    print("RAM v2 — create analyst console account\n")

    username = _prompt("Username")  # required, no default
    if store.get_user(username):  # pre-check for a friendlier error than a DB exception
        print(f"\nError: a user named {username!r} already exists.")
        return 1  # non-zero exit signals failure to the shell/CI

    display_name = _prompt("Display name", default=username)  # defaults to username if blank

    role = _prompt("Role (analyst/admin)", default="analyst")  # defaults to least-privileged role
    if role not in VALID_ROLES:
        print(f"\nError: role must be one of {VALID_ROLES}.")
        return 1

    # Read the password with echo suppressed (see getpass note at the top). Asking
    # twice (below) is the classic "type it again to confirm" trick to catch typos.
    # getpass suppresses terminal echo so the password is never shown on screen
    password = getpass.getpass("Password: ")
    if len(password) < 8:  # minimum length enforced client-side before hashing
        print("\nError: password must be at least 8 characters.")
        return 1
    if getpass.getpass("Confirm password: ") != password:  # catch typos via double entry
        print("\nError: passwords do not match.")
        return 1

    try:
        # Hash the password (never store plaintext) and persist the new user row
        user_id = store.create_user(username, hash_password(password), display_name, role)
    except psycopg.errors.UniqueViolation:
        # Race with another process/CLI invocation creating the same username
        # between our pre-check above and this INSERT — the DB's unique
        # constraint is the real guard, this is just a nicer error message
        print(f"\nError: a user named {username!r} already exists.")
        return 1

    # Account creation is consequential — record it (attributed to the new user,
    # noting it was a CLI bootstrap action since there is no logged-in session here).
    store.write_audit(
        username, "user_create", target_type="user", target_id=str(user_id),
        after={"username": username, "display_name": display_name, "role": role},
        detail="created via create_user CLI",
    )

    print(f"\nCreated user {username!r} (id={user_id}, role={role}).")
    return 0  # success


# Only run when invoked directly (e.g. `python -m app.console.create_user`),
# not when imported — sys.exit propagates main()'s return value as the exit code
if __name__ == "__main__":
    sys.exit(main())
