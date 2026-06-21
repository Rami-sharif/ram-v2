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
import json
import logging
import os
import sys

try:
    import requests
except ModuleNotFoundError:
    print("custom-ramv2: missing 'requests' module")
    sys.exit(1)

WAZUH_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s ram-v2 %(levelname)s: %(message)s",
)
log = logging.getLogger("custom-ramv2")


def main(argv):
    if len(argv) < 4:
        log.error("bad arguments: expected alert_file and hook_url, got %s", argv[1:])
        sys.exit(2)

    alert_file, hook_url = argv[1], argv[3]
    try:
        with open(alert_file, "r") as fh:
            alert = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("could not read alert file %s: %s", alert_file, exc)
        sys.exit(3)

    rule = alert.get("rule", {})
    log.info(
        "forwarding alert id=%s rule=%s level=%s -> %s",
        alert.get("id"), rule.get("id"), rule.get("level"), hook_url,
    )
    try:
        resp = requests.post(hook_url, json=alert, timeout=20)
        log.info("agent responded HTTP %s", resp.status_code)
        if resp.status_code >= 400:
            log.error("agent error body: %s", resp.text[:500])
    except requests.RequestException as exc:
        log.error("failed to POST alert to agent: %s", exc)
        sys.exit(4)


if __name__ == "__main__":
    main(sys.argv)
