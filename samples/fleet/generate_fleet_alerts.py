"""Generate and inject a diverse fleet of synthetic alerts straight into the agent webhook.

WHY THIS EXISTS
Only agent 000 (wazuh.manager) is registered on this deployment, so every alert that
arrives through the real Wazuh path reports the same host. The triage queue ends up
looking like a single machine having a very bad day, which makes the console hard to
read and hides whether the agent actually uses host context in its reasoning.

These alerts are POSTed DIRECTLY to /webhook/wazuh, deliberately bypassing Wazuh. That
is the point: it lets us describe hosts and log sources that do not exist here (a domain
controller, a finance workstation, a Kubernetes node) without registering real agents.

Everything else about the pipeline is real -- the agent investigates, triages, writes its
record and its memory exactly as it would for a genuine alert.

A MIX ON PURPOSE
Roughly a third of these are benign (a completed backup, a routine login, a package
update). Without them this only proves the agent can shout about attacks; the benign ones
are the only way to see whether it correctly stays quiet, which is the harder half.

USAGE
    python samples/fleet/generate_fleet_alerts.py                  # inject all
    python samples/fleet/generate_fleet_alerts.py --dry-run        # print, inject nothing
    python samples/fleet/generate_fleet_alerts.py --only ransom    # name substring filter
    python samples/fleet/generate_fleet_alerts.py --delay 40       # seconds between alerts
"""
import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# ?wait=1 asks the webhook to investigate INLINE and return the verdict, instead of its
# normal behaviour of acknowledging immediately and investigating in the background. Wazuh
# never sets this; it exists so injectors like this one can print what the agent decided.
WEBHOOK = "http://localhost:8000/webhook/wazuh?wait=1"

# The imaginary fleet: name -> (agent id, host ip). Chosen to span the kinds of machine a
# small company actually runs, so alerts differ by ROLE and not just by hostname.
FLEET = {
    "web-server-01":  ("001", "10.0.0.5"),     # public-facing web server (DMZ)
    "db-server-01":   ("002", "10.0.20.11"),   # database, holds the crown jewels
    "dc-01":          ("003", "10.0.30.10"),   # Windows domain controller
    "finance-ws-14":  ("004", "10.0.40.14"),   # finance staff workstation
    "mail-server-01": ("005", "10.0.10.7"),    # mail gateway
    "fw-edge-01":     ("006", "10.0.0.1"),     # perimeter firewall
    "backup-srv-02":  ("007", "10.0.50.2"),    # nightly backup server
    "k8s-node-03":    ("008", "10.0.60.3"),    # container host
}


def alert(name, host, level, rule_id, desc, groups, data, full_log,
          mitre=None, location="syslog", minutes_ago=0):
    """Build one Wazuh-shaped alert. Field names mirror what Wazuh really emits, because
    the agent's tools read them (data.srcip, rule.mitre.id, agent.name and so on)."""
    agent_id, agent_ip = FLEET[host]
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    rule = {"level": level, "description": desc, "id": rule_id, "groups": groups}
    if mitre:
        rule["mitre"] = mitre
    return {"_name": name, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "id": f"{int(ts.timestamp())}.{abs(hash(name)) % 100000}", "location": location,
            "rule": rule, "agent": {"id": agent_id, "name": host, "ip": agent_ip},
            "data": data, "full_log": full_log}


def build_alerts():
    """The fleet's alerts, ordered so the queue reads like a plausible day."""
    return [
        # ---------------- BENIGN: the agent should auto-close these ----------------
        alert("benign_backup_ok", "backup-srv-02", 3, "530",
              "Scheduled nightly backup completed successfully.",
              ["ossec", "cron"], {"srcuser": "backup"},
              "backup-runner[8812]: nightly backup of /srv completed: 412 GiB, 0 errors, duration 51m",
              minutes_ago=55),
        alert("benign_admin_login", "finance-ws-14", 3, "5715",
              "sshd: authentication success.",
              ["syslog", "sshd", "authentication_success"],
              {"srcip": "10.0.40.9", "srcuser": "m.hassan", "dstuser": "m.hassan"},
              "sshd[2210]: Accepted publickey for m.hassan from 10.0.40.9 port 51222 ssh2: RSA SHA256:9Lk2v...",
              mitre={"id": ["T1078"], "tactic": ["Defense Evasion"], "technique": ["Valid Accounts"]},
              minutes_ago=48),
        alert("benign_pkg_update", "web-server-01", 3, "2932",
              "Package updated via package manager.",
              ["syslog", "package_management"], {"srcuser": "root"},
              "dpkg: nginx upgraded 1.24.0-2ubuntu7 -> 1.24.0-2ubuntu7.3 (security update)",
              minutes_ago=41),
        alert("benign_cert_renew", "mail-server-01", 4, "40701",
              "TLS certificate renewed automatically.",
              ["ossec", "tls"], {"srcuser": "acme"},
              "certbot[1190]: renewed certificate for mail.example.com, expires 2026-10-16",
              minutes_ago=36),

        # ---------------- SUSPICIOUS: judgement calls in the middle band ----------------
        alert("port_scan_edge", "fw-edge-01", 8, "40101",
              "Multiple connection attempts to closed ports from a single source.",
              ["firewall", "recon"],
              {"srcip": "91.202.10.20", "dstip": "10.0.0.5", "dstport": "multiple"},
              "kernel: [UFW BLOCK] SRC=91.202.10.20 DST=10.0.0.5 PROTO=TCP 41 ports in 30s, all dropped",
              mitre={"id": ["T1046"], "tactic": ["Discovery"], "technique": ["Network Service Scanning"]},
              minutes_ago=30),
        alert("new_admin_user", "db-server-01", 9, "5902",
              "New user added to the administrators group.",
              ["syslog", "adduser", "account_changed"],
              {"srcuser": "root", "dstuser": "svc_report"},
              "useradd[4471]: new user: name=svc_report, UID=1104, GID=27(sudo), home=/home/svc_report",
              mitre={"id": ["T1136.001"], "tactic": ["Persistence"], "technique": ["Create Account"]},
              minutes_ago=26),
        alert("phishing_attachment", "mail-server-01", 10, "87105",
              "Mail attachment matched malicious signature.",
              ["mail", "malware"],
              {"srcip": "185.199.108.153", "srcuser": "billing@invoice-secure.net",
               "dstuser": "m.hassan@example.com",
               "sha256": "44d88612fea8a8f36de82e1278abb02f6f0e2f6f4b3c9cba2e3a4d5e6f7a8b9c"},
              "postfix/amavis: BANNED attachment 'Invoice_8841.xlsm' to m.hassan@example.com, macro/dropper signature",
              mitre={"id": ["T1566.001"], "tactic": ["Initial Access"], "technique": ["Spearphishing Attachment"]},
              minutes_ago=22),

        # ---------------- ATTACKS: should escalate ----------------
        alert("kerberoast_dc", "dc-01", 12, "60112",
              "Multiple Kerberos service tickets requested with weak encryption (possible Kerberoasting).",
              ["windows", "authentication", "kerberos"],
              {"srcip": "10.0.40.14", "srcuser": "m.hassan", "dstuser": "svc_sql"},
              "EventID 4769: 28 TGS requests, RC4-HMAC encryption, from 10.0.40.14 in 90 seconds",
              mitre={"id": ["T1558.003"], "tactic": ["Credential Access"], "technique": ["Kerberoasting"]},
              location="EventChannel", minutes_ago=18),
        alert("db_mass_export", "db-server-01", 12, "80210",
              "Unusually large database export by an application account.",
              ["database", "exfiltration"],
              {"srcip": "10.0.0.5", "srcuser": "svc_report", "dstip": "185.220.101.55"},
              "postgres[9931]: COPY customers TO STDOUT executed by svc_report: 2,412,880 rows (1.8 GiB) "
              "streamed to 185.220.101.55; 7-day baseline for this account is 4 MiB/day",
              mitre={"id": ["T1041"], "tactic": ["Exfiltration"], "technique": ["Exfiltration Over C2 Channel"]},
              minutes_ago=13),
        alert("container_escape", "k8s-node-03", 12, "87301",
              "Container attempted to mount the host filesystem (possible container escape).",
              ["docker", "container", "privilege_escalation"],
              {"srcuser": "root", "file": "/proc/1/root"},
              "runtime: pod 'api-worker-7c9' opened /proc/1/root and wrote /host/etc/cron.d/.sysupdate",
              mitre={"id": ["T1611"], "tactic": ["Privilege Escalation"], "technique": ["Escape to Host"]},
              minutes_ago=9),
        alert("ransomware_finance", "finance-ws-14", 14, "100503",
              "Mass file rename with known ransomware extension.",
              ["syscheck", "ransomware"],
              {"srcuser": "m.hassan", "file": "/mnt/finance-share/Q3_forecast.xlsx.lockbit"},
              "syscheck: 1,847 files renamed to *.lockbit under /mnt/finance-share in 4 minutes; "
              "ransom note RESTORE-MY-FILES.txt created in 39 directories",
              mitre={"id": ["T1486"], "tactic": ["Impact"], "technique": ["Data Encrypted for Impact"]},
              location="syscheck", minutes_ago=4),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--webhook", default=WEBHOOK)
    ap.add_argument("--only", help="only alerts whose name contains this substring")
    ap.add_argument("--delay", type=float, default=8.0,
                    help="seconds between alerts (each triggers a real investigation)")
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent, send nothing")
    args = ap.parse_args()

    alerts = build_alerts()
    if args.only:
        alerts = [a for a in alerts if args.only in a["_name"]]
    if not alerts:
        raise SystemExit("no alerts matched")

    print(f"{len(alerts)} synthetic alert(s) across {len(FLEET)} hosts")
    for i, a in enumerate(alerts, 1):
        name = a.pop("_name")
        host, lvl = a["agent"]["name"], a["rule"]["level"]
        print(f"  [{i}/{len(alerts)}] {name:<22} {host:<15} level {lvl:<3}", end="", flush=True)
        if args.dry_run:
            print("  (dry run)")
            continue
        try:
            req = urllib.request.Request(
                args.webhook, data=json.dumps(a).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            # Generous timeout: the response only comes back once the agent has finished
            # its whole investigation, which takes tens of seconds.
            with urllib.request.urlopen(req, timeout=180) as resp:
                body = json.loads(resp.read())
            an = body.get("analysis", {})
            tri = (body.get("triage") or {}).get("action", "-")
            print(f"  -> {an.get('severity_score')} {an.get('severity_label')} / {tri}")
        except urllib.error.HTTPError as exc:
            print(f"  -> HTTP {exc.code}: {exc.read()[:120]}")
        except Exception as exc:  # noqa: BLE001
            print(f"  -> FAILED: {exc}")
        if i < len(alerts):
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
