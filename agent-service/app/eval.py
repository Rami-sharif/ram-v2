"""Scored evaluation harness: does the agent still give good verdicts?

WHAT THIS FILE IS, FOR A NEWCOMER:
The agent's output is produced by a language model, so it cannot be checked by a normal unit
test asserting one exact value — the same alert can score 88 one run and 91 the next. What we
CAN pin down is the DECISION: a benign cron job must never reach an analyst, and ransomware
must never be silently auto-closed. So each labelled sample carries a score BAND anchored to
the triage thresholds (see samples/expectations.json), and this harness replays every sample
and reports which ones fall outside their band.

WHY IT DOES NOT USE THE WEBHOOK:
Running these through POST /webhook/wazuh would write a memory row and an investigation for
every sample, on every run. That is fatal for an evaluation: the harness would contaminate
the very history it is measuring, and repeated runs would reinforce whatever verdict the
agent gave last time — the exact self-confirmation loop we are trying to detect. So this
replays only the READ half of the pipeline:

    retrieve memory context  ->  run the agent  ->  compare the verdict to its band

and deliberately skips memory write-back, triage, case creation and investigation
recording. Nothing is mutated, so the harness is safe to run as often as you like.

USAGE (inside the agent container):
    python -m app.eval                     # run every labelled sample
    python -m app.eval --only benign       # only samples whose name contains "benign"
    python -m app.eval --json results.json # also write machine-readable results
    python -m app.eval --baseline old.json # flag changes vs a previous run (drift)

Exit code is 0 when every case passes and 1 otherwise, so it can gate a build.
"""
import argparse  # command-line flags
import json  # load samples/expectations, emit machine-readable results
import logging  # quiet the pipeline's own chatter so the report is readable
import sys  # exit codes
import time  # per-case duration, to spot latency regressions
from pathlib import Path  # filesystem paths for the sample/expectation files
from typing import Any, Optional

from .agent import run_agent  # the investigation loop under test
from .webhook import _retrieve_memory, normalize_alert  # READ-only half of the pipeline

# Default location of the samples directory (mounted read-only into the container).
DEFAULT_SAMPLES = Path("/app/samples")


def _load_cases(samples_dir: Path) -> list[dict[str, Any]]:
    """Read the labelled expectation set that defines 'a good result' for each sample."""
    path = samples_dir / "expectations.json"
    if not path.exists():
        raise SystemExit(f"no expectation set at {path} — cannot evaluate without ground truth")
    return json.loads(path.read_text()).get("cases", [])


def _run_one(samples_dir: Path, case: dict[str, Any]) -> dict[str, Any]:
    """Replay ONE sample through retrieval + the agent and score it against its band.

    Returns a result dict; never raises, so one broken sample cannot abort the whole run."""
    name = case["sample"]
    started = time.perf_counter()
    result: dict[str, Any] = {
        "sample": name, "min_score": case["min_score"], "max_score": case["max_score"],
        "why": case.get("why", ""),
    }
    try:
        payload = json.loads((samples_dir / name).read_text())
        alert = normalize_alert(payload)
        # Same memory context the real pipeline would build — retrieval is read-only.
        _embedding, _memories, memory_context = _retrieve_memory(alert)
        # The agent under test. Its write-back/triage/recording are deliberately NOT called.
        analysis, _enrichment, tool_trace = run_agent(alert, memory_context)
    except Exception as exc:  # noqa: BLE001 - a failing sample is a result, not a crash
        result.update({"status": "ERROR", "error": str(exc),
                       "duration_s": round(time.perf_counter() - started, 1)})
        return result

    score = analysis.severity_score
    result.update({
        "status": "PASS" if case["min_score"] <= score <= case["max_score"] else "FAIL",
        "score": score,
        "label": analysis.severity_label,
        "attack_type": analysis.attack_type,
        "tools": [t.get("tool") for t in tool_trace],
        "summary": analysis.summary,
        "duration_s": round(time.perf_counter() - started, 1),
    })
    return result


def _report(results: list[dict[str, Any]], baseline: Optional[dict[str, Any]]) -> int:
    """Print the human-readable report and return the process exit code."""
    # Map a previous run's scores by sample name so we can flag drift.
    prior = {r["sample"]: r for r in (baseline or {}).get("results", [])} if baseline else {}

    print()
    print(f"{'sample':<40} {'expected':>10}  {'actual':>16}  {'':>6} {'drift':>8}")
    print("-" * 88)
    for r in results:
        band = f"{r['min_score']}-{r['max_score']}"
        if r["status"] == "ERROR":
            actual, mark = "ERROR", "!!"
        else:
            actual = f"{r['score']:>3} {r['label']}"
            mark = "ok" if r["status"] == "PASS" else "FAIL"
        # Drift vs the baseline run, if one was supplied.
        drift = ""
        p = prior.get(r["sample"])
        if p and p.get("score") is not None and r.get("score") is not None:
            delta = r["score"] - p["score"]
            if delta:
                drift = f"{delta:+d}"
            # A status flip is far more important than a score wobble — call it out.
            if p.get("status") != r["status"]:
                drift = f"{drift} {p.get('status')}->{r['status']}".strip()
        print(f"{r['sample']:<40} {band:>10}  {actual:>16}  {mark:>6} {drift:>8}")

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = [r for r in results if r["status"] != "PASS"]
    print("-" * 88)
    print(f"{passed}/{len(results)} passed")

    if failed:
        print("\nFailures — each one is an operational difference, not score jitter:")
        for r in failed:
            if r["status"] == "ERROR":
                print(f"\n  {r['sample']}: ERROR {r.get('error')}")
                continue
            # Explain the failure in terms of what would actually happen to the alert.
            got, lo, hi = r["score"], r["min_score"], r["max_score"]
            direction = ("scored ABOVE its band — benign activity would reach an analyst"
                         if got > hi else
                         "scored BELOW its band — real activity would be under-triaged")
            print(f"\n  {r['sample']}: {got} ({r['label']}) vs expected {lo}-{hi} — {direction}")
            print(f"    expected because: {r['why']}")
            print(f"    agent said      : {(r.get('summary') or '')[:160]}")
            print(f"    tools used      : {r.get('tools')}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Score the agent's verdicts against labelled samples.")
    ap.add_argument("--samples", default=str(DEFAULT_SAMPLES), help="samples directory")
    ap.add_argument("--only", help="only run samples whose name contains this substring")
    ap.add_argument("--json", help="write machine-readable results to this path")
    ap.add_argument("--baseline", help="previous --json results file, to report drift against")
    args = ap.parse_args()

    # The pipeline logs a lot per alert; keep the report readable.
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("httpx", "app.agent", "app.memory", "app.webhook", "app.triage"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    samples_dir = Path(args.samples)
    cases = _load_cases(samples_dir)
    if args.only:
        cases = [c for c in cases if args.only in c["sample"]]
    if not cases:
        raise SystemExit("no cases matched")

    baseline = json.loads(Path(args.baseline).read_text()) if args.baseline else None

    print(f"Evaluating {len(cases)} labelled sample(s). "
          f"Read-only: no memory, investigation or case is written.")
    results = []
    for i, case in enumerate(cases, 1):
        print(f"  [{i}/{len(cases)}] {case['sample']} ...", flush=True)
        results.append(_run_one(samples_dir, case))

    code = _report(results, baseline)
    if args.json:
        Path(args.json).write_text(json.dumps({"results": results}, indent=2, default=str))
        print(f"\nresults written to {args.json}")
    return code


if __name__ == "__main__":
    sys.exit(main())
