# Changes — agent reliability, severity calibration, and detection coverage

Branch: `fix/agent-reliability-and-severity-calibration`
Date: 2026-07-18 / 2026-07-19

This documents one working session. It began as "are the agent's verdicts any good, and
why the false positives?" and ended up uncovering four correctness bugs that were losing
alerts outright. Findings are recorded with the evidence that produced them, including the
places where a first attempt was wrong, because the wrong turns explain why the final
shape is what it is.

---

## Summary

| # | Change | Why |
|---|---|---|
| 1 | Severity rubric anchored on attack stage | Scale had collapsed: 10 of 14 samples scored ≥90 |
| 2 | `submit_analysis` withheld until a tool runs | Agent could close a case from memory alone |
| 3 | Required `evidence` field | Score had to be backed by findings from *this* run |
| 4 | Unverified memories discounted + labelled | Agent was citing its own unreviewed guesses as proof |
| 5 | Duplicate tool calls blocked | Same tool + identical args re-called; caused throttling |
| 6 | Webhook responds immediately, investigates in background | Slow investigations were being **destroyed** |
| 7 | Event loop no longer blocked | One alert froze the entire service |
| 8 | `investigation_chat` added to delete cleanup | Some investigations were undeletable |
| 9 | Audit + delete made atomic | Audit log claimed deletions that never happened |
| 10 | Wazuh forward threshold 10 → 6 | Agent was blind to *successful* web attacks |
| 11 | Custom rules 100200 / 100201 | Successful traversal / web shell produced **no alert at all** |
| 12 | Eval harness + labelled expectations | There was no way to measure any of this |
| 13 | Fleet alert generator | Every alert reported the same host |

---

## 1. Severity compression

**Problem.** The scale was effectively binary. Measured across the 14 labelled samples:

```
0, 10, 80, 85, 90, 95, 95, 95, 95, 95, 95, 98, 100, 100
```

Ten of fourteen at ≥90, and **nothing at all between 10 and 80**. A port scan and live
ransomware both scored ~95, so severity carried almost no information for prioritising.

**Cause.** Two things. `severity_score` was documented to the model as only
`"0 (benign) to 100 (critical)"` — no anchors. And the system prompt said *"Let the Wazuh
rule level drive severity"*, while nearly every rule worth alerting on ships at level
10–12, which pins everything to the top of the range.

**Fix.** Bands anchored on **attack stage** — how far the attacker actually got — in
`tools/submit.py`, plus a hard rule: no score ≥80 without concrete evidence the attack
*succeeded*. The rule-level instruction was removed and replaced with an explicit warning
that rule level measures how noisy a rule is, not how damaging the event is.

**Result.**

| | Before | After |
|---|---|---|
| Scored ≥90 | 10 / 14 | 4–5 / 14 |
| In the 40–79 band | **0** | 3–4 |
| Eval pass rate | 10 / 14 | **13 / 14** |

Later confirmed end-to-end on real alerts, where the bands separate cleanly:
30 = not an attack · 65 = blocked attempt · 70 = attempt · 80 = succeeded · 85–95 = compromise.

---

## 2–4. The self-confirmation loop

**Problem.** A completely routine alert (admin logging in by SSH key from a known
workstation) was consistently scored `critical(95)`.

**Cause.** The agent's own earlier verdict for that host sat in memory at similarity
1.000, unreviewed by any human, and the agent cited it as corroboration. Because
unreviewed verdicts are written back to memory, one early mistake kept re-confirming
itself. Nothing forced the agent to gather current evidence: prior alerts are injected
into the prompt *before* any tool runs, so it could call `submit_analysis` on turn 1 and
never investigate at all.

**Fixes.**

- Unverified memories weighted `0.85` (deliberately **below** neutral) and labelled in
  the prompt as `⚠ UNVERIFIED (this system's own earlier guess — no human checked it)`.
- `submit_analysis` is withheld from the tool allowlist until at least one investigative
  tool has been *attempted* (`agent.py`). Keyed on attempts, not successes, so a failing
  upstream service can't trap the agent in a loop.
- New required `evidence` field: 2–5 concrete findings, each attributed to its source.
  Attribution wording was tightened after the model was caught crediting tools it had
  never called — it must write `(tool_name)` only for tools actually run this turn, and
  `(alert log)` or `(prior case)` otherwise.
- Prompt additions: agreeing with an UNVERIFIED prior is not corroboration; counting
  unverified priors does not make them true; **rarity is not malice**; **familiarity is
  reassuring, not suspicious**.

**Result.** The flagship false positive went `95` → `10–15` typically. Honest caveat: it
is **not stable** — across runs it has scored 10, 15, 45, 50, 55, 70, 75. Root cause is
data, not code: four unreviewed `critical(95)` records for that benign IP remain in the
database. Recommended remedy is an analyst override through the console (the designed
feedback path), not deleting rows.

---

## 5. Duplicate tool calls

**Problem.** Observed live:

```
iter=5  get_alert_statistics  group_by: data.dstip  "...appears in alerts on the host."
iter=6  get_alert_statistics  group_by: data.dstip  "...appears in alerts on this host."
```

Identical tool, identical arguments, reworded justification. Measured across 35
investigations: **7 (20%) called the same tool 3+ times.** Each repeat is a model
round-trip; once the API began throttling, iterations stretched from ~2s to ~4 minutes and
an investigation ran 8+ minutes without producing a verdict.

**Fix.** `agent.py` caches `(tool, canonical args)` per run. An exact repeat is answered
from cache without re-dispatching, and the model is told plainly that it already has the
result. After `agent_max_duplicate_calls` (default 2) repeats the loop stops and forces a
verdict. `reason` is excluded from the cache key precisely because the model rewords it.

**Verified** with a deterministic test (mocked model forced to repeat 3×): 1 actual
dispatch, 2 repeats marked, loop cut short, real verdict produced. Eval unchanged at
13/14. Repeats appear in the console trace as `repeat (cached)` so the audit record stays
honest about what was asked versus what ran.

**Caveat.** This cannot prevent the round-trip that *produces* a repeat — that request has
already happened. It prevents re-execution and the *next* repeat.

---

## 6–7. Alerts were being destroyed

The most serious findings, and neither was visible while alerts were POSTed directly to
the webhook. They only appeared once logs were injected through the real Wazuh path.

### 6. Investigations died when the caller hung up

```
15:37:38  forwarding alert rule=5763 level=10
15:37:58  ERROR: Read timed out. (read timeout=20)
```

The integration waited 20s; a real investigation took 37s. Wazuh disconnected, the work
was abandoned mid-investigation, and **no record of the alert survived anywhere**.

First attempt raised the timeout to 180s. **That was the wrong fix, and it was proved
wrong later in the same session** when a level-14 ransomware alert was lost the same way.
A timeout only chooses which slow investigations get discarded — and slow correlates with
complex, which correlates with severe. The failure mode preferentially ate the alerts that
mattered most.

**Real fix.** The webhook now returns `202 Accepted` immediately and investigates in a
detached task (`asyncio.create_task`), so the work survives the caller disconnecting.
`?wait=1` preserves the old synchronous behaviour for testing and sample injectors.

Concurrency is bounded (`webhook_max_concurrent_investigations`, default 3) so bursts
queue instead of piling onto a throttled API. Strong references to in-flight tasks are
kept deliberately: asyncio holds only a *weak* reference, so an unreferenced task can be
garbage-collected mid-run — which is the same silent alert loss through another door.

Integration timeout reduced 180s → 30s, since it now covers delivery only, with a note not
to raise it again.

| | Before | After |
|---|---|---|
| Wazuh wait for reply | 13–40 s | **6 ms** |
| Caller disconnects | work destroyed | completes anyway |
| 8-alert burst | ~3 min, alerts lost | 0.02 s to accept, **0 lost** |

### 7. One alert froze the whole service

```python
async def wazuh_webhook(request):
    result = process_alert(payload)   # blocking, minutes long
```

An `async def` route runs *on* the event loop, so a blocking call inside it freezes the
entire server — console, health checks, every other alert.

| | Before | After |
|---|---|---|
| `/health` | **no response in 30 s** | 0.003 s |
| One model call | **~4 min** | 1.1 s |

The 4-minute figure was the striking part: the model was never slow. Blocking the loop
from inside a coroutine starved the HTTP machinery the call itself depended on. Fixed with
`run_in_threadpool`.

---

## 8–9. Two bugs behind "why can't I delete Investigation #1?"

**8.** Four tables carry a foreign key to `alert_investigations`, none with cascade. The
delete code cleared three and missed `investigation_chat`. Any investigation an analyst
had chatted about became undeletable. The docstring said *"the two child tables"* while
the code deleted three — it had drifted when that table was added. Fixed by driving both
the single and bulk delete paths from one shared `_INVESTIGATION_CHILD_TABLES` list, since
duplicating the table names is how they fell out of step originally.

**9.** The worse bug. The audit row was written in its own transaction *before* the
delete, intending "never delete without a record". When the delete then failed, the
committed audit row asserted a deletion that had not happened — **six phantom entries** for
investigation #1, which still existed. Audit and deletes now commit in one transaction:
no unaudited delete, and no audit for a delete that did not occur.

The phantom rows were deliberately **left in place**. Deleting audit history to tidy up a
bug is a worse habit than a wrong entry, and they are the evidence the bug existed.

---

## 10–11. Detection coverage

**Correction first.** An earlier claim in this session — *"only SSH brute force reaches the
AI"* — was **wrong**, and the cause was bad test data, not the system. The web-scan rule
needs 14 hits in 90s and only 9 were sent; the SQL-injection test used malformed future
timestamps that broke Wazuh's frequency window. With correct input, both fire.

**The real gap** is systemic and runs the wrong way round: **the stock ruleset scores a web
attack that SUCCEEDED lower than the same attack when it FAILED.**

| Attack | Rule | Level | Reached agent (before) |
|---|---|---|---|
| SQL injection ×10, failed | 31103 → 31152 | 10 | yes |
| SQL injection ×1, **succeeded** | 31106 | 6 | no |
| Path traversal, blocked | 31104 | 6 | no |
| Path traversal, **succeeded** | 31108 | **0** | **no alert generated at all** |
| Web shell command run | 31100 | **0** | **no alert generated at all** |

**Fix 10.** Integration threshold 10 → 6, which surfaces rule 31106. Deliberately *not* 5:
measured, level 5 adds 144 more alerts that are overwhelmingly raw components (individual
failed passwords, individual 400s) already summarised by the level-10 rules, so the agent
would re-investigate one incident ~100 times rather than filter anything new.

**Fix 11.** Level 0 means no alert exists, so no threshold can surface it. New rules in
`wazuh/rules/local_rules.xml`:

- `100200` (level 10) — path traversal / sensitive file read that returned 200
- `100201` (level 12) — web shell or command execution that returned 200

Raising 31100/31108 directly **would have been catastrophic**: 31100 is the parent of every
web access-log line and 31108 is "normal successful request, ignore it". Both rules
therefore require a dangerous URL pattern **and** a success status.

Verified no flood: `/index.html`, `/assets/app.css`, `/api/orders?id=42` all stay silent,
and `search.php?q=commander` does not match despite containing `cmd` — the pattern is
`cmd=`, not bare `cmd`. Live: 2 attacks caught, **0 alerts from 5 normal requests**.

**Outcome.** The agent then rated a single successful SQL injection (80, flagged) above ten
failed ones (70) — correcting Wazuh's own inverted prioritisation. A successful traversal
scored 95 after the agent correlated it with a web-shell execution from the same IP that it
found on its own.

---

## 12–13. Measurement and test data

**Eval harness** (`app/eval.py`, `samples/expectations.json`) — replays 14 labelled samples
against score bands anchored to the real triage thresholds (`<40` auto-closes, `≥80`
escalates), so a failure means an operational difference rather than score jitter. It runs
**retrieval + agent only**, deliberately skipping write-back, triage and recording: going
through the webhook would contaminate the very history it measures and reinforce the
previous run's verdict — the exact self-confirmation loop being tested for.

Two expectation labels were corrected, both recorded in the file with reasoning:
- `wazuh_ssh_bruteforce` — the agent was **right**; an analyst-confirmed record showed a
  successful login from that IP.
- `wazuh_malware_file` — the agent correctly identified EICAR as a harmless test file. The
  band had **pre-registered** this prediction before it happened.

**Fleet generator** (`samples/fleet/generate_fleet_alerts.py`) — 11 synthetic alerts across
8 imaginary hosts, POSTed directly so hosts that don't exist here (domain controller,
Kubernetes node, finance workstation) can appear in the queue. About a third are benign on
purpose: without them the exercise only proves the agent can escalate, and staying quiet is
the harder half. Use `--delay 30` or higher; the default will trigger throttling.

---

## Known issues (not fixed)

1. **No automated tests, no CI.** No `tests/` directory, no workflows, no test framework in
   dependencies. Every bug here was found by hand and could silently return. The eval
   harness is the only automated check and is wired into nothing.
2. **Zero human review coverage** — `verdict_reviews: 0` against 35 investigations. Every
   learning-loop mechanism (feedback weighting, override precedence) is inert for want of
   input. This is *why* the false-positive loop bit: with no human verdicts, the agent's
   only history is its own guesses.
3. **`agent_accuracy()` is dead code** — never called anywhere. Pointless until (2).
4. **"No history" still means whatever suits the current guess** — treated as *suspicious*
   for `benign_low`, as *reassuring* for the new-admin-account alert. Damped, not made
   consistent.
5. **Correlation gap.** A new admin account (`svc_report`) was auto-closed at 30; thirteen
   minutes later the same account exfiltrated 1.8 GiB and scored 90. The exfiltration
   investigation never noticed the account was minutes old — history is searched by IP, not
   by username.
6. **No durable queue.** Restarting the container drops in-flight investigations.
7. **`benign_low` remains unstable** (see §2–4).
8. **Other level-0 blind spots probably remain.** Only traversal and web shell were fixed;
   the rest of the ruleset was never audited for the same inverted pattern, and it appeared
   twice.
9. **Concurrency limit of 3 is a guess** from one day's throttling, not a tuned value.
10. `/var/log/ramv2-demo.log` does not survive container recreation.

## Suggested order of work

1. Tests + eval harness in CI — stops these fixes silently regressing
2. Review ~10 verdicts in the console — switches the learning loop on
3. Wire up `agent_accuracy()` — then progress becomes measurable
4. Audit the ruleset for further "success scores lower than failure" cases

## Locked invariants — verified intact

`gemini-2.5-flash` · `gemini-embedding-001` @ 768 dims · no raw SQL for the LLM ·
`alert_investigations` write-once trigger present · investigation agent strictly read-only.
