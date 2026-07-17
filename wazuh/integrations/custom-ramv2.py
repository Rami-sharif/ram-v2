#!/usr/bin/env python3
"""RAM v2 Wazuh integration.

Wazuh's integrator daemon calls this with:
    argv[1] = path to a file containing the single alert as JSON
    argv[2] = api key from <api_key> (unused here)
    argv[3] = hook url from <hook_url> (the agent webhook)

We forward the alert JSON verbatim to the agent webhook so the agent sees the
exact Wazuh alert shape. Errors are logged to integrations.log, never raised back
into the integrator in a way that would lose the alert silently.
"""
# Standard library: encode/decode the alert JSON payload.
import json
# Standard library: write structured log lines to integrations.log.
import logging
# Standard library: derive filesystem paths relative to this script.
import os
# Standard library: read argv and control the process exit code.
import sys

# The Wazuh framework Python bundles `requests`, but guard the import anyway
# so a misconfigured interpreter fails with a clear message instead of a
# raw traceback that the integrator daemon would otherwise swallow.
try:
    import requests
except ModuleNotFoundError:
    # Printed to stderr/stdout since logging isn't configured yet at this
    # point (and the log file path itself isn't set up until below).
    print("custom-ramv2: missing 'requests' module")
    # Exit code 1 signals a fatal environment problem to the integrator.
    sys.exit(1)

# Wazuh install root, derived by walking two directories up from this
# script's real path (integrations/custom-ramv2.py -> integrations -> root).
WAZUH_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# Standard Wazuh integrations log file, so failures here show up alongside
# every other integration's diagnostics.
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")

# Configure the root logging setup once at import time: append to the
# shared integrations.log, at INFO level, with a timestamped line format
# that includes our integration's tag for easy grepping.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s ram-v2 %(levelname)s: %(message)s",
)
# Named logger (rather than the bare root logger) so log lines are
# attributable to this specific integration if the format is ever changed.
log = logging.getLogger("custom-ramv2")


def main(argv):
    # The integrator always calls us with 4 positional args (script name +
    # 3 real args); fewer means something is badly misconfigured upstream.
    if len(argv) < 4:
        log.error("bad arguments: expected alert_file and hook_url, got %s", argv[1:])
        # Distinct exit code (2) so this failure mode is distinguishable in
        # process-exit-based monitoring from the other error paths below.
        sys.exit(2)

    # Only argv[1] (alert file path) and argv[3] (hook URL) are needed;
    # argv[2] (API key) is intentionally unused per the module docstring.
    alert_file, hook_url = argv[1], argv[3]
    try:
        # Read and parse the single alert JSON blob Wazuh wrote to disk for
        # this invocation.
        with open(alert_file, "r") as fh:
            alert = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        # Covers both "file missing/unreadable" and "file isn't valid
        # JSON" without losing the alert silently — it's logged instead.
        log.error("could not read alert file %s: %s", alert_file, exc)
        # Distinct exit code (3) for "couldn't read/parse the alert file".
        sys.exit(3)

    # Pull out the "rule" sub-object defensively (default {}) purely for
    # logging context; the full alert is still forwarded unmodified below.
    rule = alert.get("rule", {})
    # Record what's about to be forwarded (alert id, rule id/level, and
    # destination) before attempting the network call, so the log has a
    # trace even if the POST itself fails.
    log.info(
        "forwarding alert id=%s rule=%s level=%s -> %s",
        alert.get("id"), rule.get("id"), rule.get("level"), hook_url,
    )
    try:
        # Forward the alert JSON verbatim (same shape Wazuh produced) to
        # the agent webhook, with a 20s timeout so a hung endpoint can't
        # block the integrator daemon indefinitely.
        resp = requests.post(hook_url, json=alert, timeout=20)
        # Log the HTTP status regardless of outcome for observability.
        log.info("agent responded HTTP %s", resp.status_code)
        if resp.status_code >= 400:
            # Truncate the response body to 500 chars to avoid flooding
            # the log with a large/unexpected error page.
            log.error("agent error body: %s", resp.text[:500])
    except requests.RequestException as exc:
        # Covers connection errors, timeouts, DNS failures, etc.; logged
        # rather than raised so the integrator doesn't see an unhandled
        # exception.
        log.error("failed to POST alert to agent: %s", exc)
        # Distinct exit code (4) for "network/delivery failure".
        sys.exit(4)


# Standard entry-point guard: only run main() when invoked directly by the
# integrator (or from the shell wrapper), not if ever imported as a module.
if __name__ == "__main__":
    main(sys.argv)
