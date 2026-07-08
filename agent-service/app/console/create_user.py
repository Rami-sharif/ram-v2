"""Interactive CLI to create an analyst console account.

Run inside the service container:

    docker compose exec agent-service python -m app.console.create_user

No credentials are accepted on the command line or via environment — the
password is read interactively with getpass and never echoed, logged, or
stored in plaintext (only its argon2 hash is persisted).
"""
import getpass
import sys

import psycopg

from . import store
from .auth import hash_password

VALID_ROLES = ("analyst", "admin")


def _prompt(label: str, *, default: str | None = None, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value or not required:
            return value
        print("  (required)")


def main() -> int:
    print("RAM v2 — create analyst console account\n")

    username = _prompt("Username")
    if store.get_user(username):
        print(f"\nError: a user named {username!r} already exists.")
        return 1

    display_name = _prompt("Display name", default=username)

    role = _prompt("Role (analyst/admin)", default="analyst")
    if role not in VALID_ROLES:
        print(f"\nError: role must be one of {VALID_ROLES}.")
        return 1

    password = getpass.getpass("Password: ")
    if len(password) < 8:
        print("\nError: password must be at least 8 characters.")
        return 1
    if getpass.getpass("Confirm password: ") != password:
        print("\nError: passwords do not match.")
        return 1

    try:
        user_id = store.create_user(username, hash_password(password), display_name, role)
    except psycopg.errors.UniqueViolation:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
