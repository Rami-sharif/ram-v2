"""The terminal submit_analysis "tool" the AI model calls to finish a case.

Background for newcomers: this system uses an LLM (a large language model — the AI
that reads the alert and reasons about it). Modern LLMs support "function calling"
(a.k.a. "tools"): instead of only replying with prose, the model can ask the program
to run a named function with structured arguments. We describe each available
function to the model as a JSON schema (a machine-readable description of the
argument names, types, and which are required). The model then returns arguments
that match that schema.

`submit_analysis` is the special LAST tool. When the model calls it, that IS the
finished triage verdict (severity, attack type, summary, next action), and the agent
loop treats that call as the signal to stop investigating. Because a later
deterministic step (the "triage router" that decides auto-close vs. escalate) reads
these exact fields, the output shape is LOCKED — do not rename or drop fields.

Unlike the other tools, this one has NO Python handler: nothing runs when it's
called. Its arguments simply become the final result."""

# The exact tool name the agent loop watches for to know "the investigation is done".
SUBMIT_ANALYSIS = "submit_analysis"

# The function-calling declaration handed to the model: it tells the model this tool
# exists, what it's for, and the precise argument schema its final answer must match.
SUBMIT_DECLARATION = {
    "name": SUBMIT_ANALYSIS,
    # Tells the model when/why to call this: only once evidence has been gathered.
    "description": "Submit the final structured triage analysis and end the investigation. "
                   "Call this once you have gathered enough evidence.",
    "parameters": {
        # Standard JSON-schema object wrapper for the function's arguments.
        "type": "object",
        "properties": {
            # Numeric 0-100 severity score the model must assign.
            #
            # The bands below exist because a bare "0 to 100" gave the model no anchors, and it
            # collapsed the scale into two values: ~0 for obvious noise and 90+ for everything
            # else. A measured run scored 10 of 14 labelled samples at >=90, so severity carried
            # almost no signal — a port scan and live ransomware both came out ~95.
            #
            # The fix is to anchor the bands on ATTACK STAGE (how far the attacker actually got)
            # rather than on the Wazuh rule level. Rule level measures "how noisy is this rule",
            # and nearly every interesting rule ships at level 10-12, so anchoring there forces
            # everything into the top of the range. Stage is what analysts actually triage on and
            # it spreads naturally across the scale.
            "severity_score": {
                "type": "integer",
                "description": (
                    "0-100. Use the FULL range - most alerts are NOT critical. Judge how far the "
                    "attack actually GOT, not how high the Wazuh rule level is:\n"
                    "0-19: routine expected activity (scheduled backups, package updates, a known "
                    "admin logging in normally).\n"
                    "20-39: unusual, but a harmless explanation fits the evidence you have.\n"
                    "40-59: suspicious and worth a human look, but nothing shows the attacker "
                    "achieved anything.\n"
                    "60-79: a real malicious ATTEMPT that did NOT succeed - port scanning, failed "
                    "brute force, a blocked or rejected exploit.\n"
                    "80-100: CONFIRMED success or active damage, where you can name the concrete "
                    "evidence: a login that succeeded after failures, a malicious VirusTotal "
                    "verdict, a web shell written to disk, files encrypted, data sent out.\n"
                    "HARD RULE: if you cannot name concrete evidence that the attack SUCCEEDED, "
                    "the score stays below 80. 'It could have succeeded' is not evidence."
                ),
            },
            # Coarse severity bucket, constrained to a fixed enum for downstream routing.
            "severity_label": {"type": "string",
                               "enum": ["info", "low", "medium", "high", "critical"]},
            # Free-text but example-guided classification of the attack observed.
            "attack_type": {"type": "string",
                            "description": "e.g. 'brute force', 'malware', 'port scan'."},
            # Optional array of MITRE ATT&CK mappings. MITRE ATT&CK is an industry
            # catalog of attacker tactics/techniques, each with an id like "T1110";
            # mapping an alert to these ids lets analysts speak a shared language.
            "mitre": {
                "type": "array", "description": "MITRE ATT&CK mappings.",
                "items": {"type": "object", "properties": {
                    "tactic": {"type": "string"}, "technique": {"type": "string"},
                    # technique_id is required per MITRE entry, e.g. T1110.
                    "technique_id": {"type": "string", "description": "e.g. T1110"},
                }, "required": ["technique_id"]},
            },
            # Short human-readable analyst summary that must cite gathered tool evidence.
            "summary": {"type": "string", "description": "2-4 sentence summary in very simple, "
                        "plain English (short sentences, everyday words), citing evidence "
                        "gathered from tools."},
            # The concrete next action recommended to a human analyst.
            "recommended_action": {"type": "string", "description": "Concrete next step, in "
                                   "simple plain English."},
            # Required so the score has to be BACKED by findings from this run. Without it the
            # model could (and did) inherit a verdict from a similar past alert without ever
            # establishing anything itself. Making the model enumerate its own findings both
            # discourages that and leaves an auditable record of what the score rested on.
            "evidence": {
                "type": "array", "items": {"type": "string"},
                "description": "2-5 short factual findings, each ending with where it came from. "
                               "Attribute honestly, because this is an audit record: write "
                               "'(<tool_name>)' ONLY for a tool you actually called during THIS "
                               "run, '(alert log)' for something read off the current alert, and "
                               "'(prior case)' for anything taken from the prior-related-alerts "
                               "block in the prompt - never credit a tool you did not call. Do "
                               "NOT offer a past alert's verdict as evidence for your score: an "
                               "earlier unreviewed guess by this system is not a finding.",
            },
        },
        # Fields the model MUST fill in; mitre is deliberately optional.
        "required": ["severity_score", "severity_label", "attack_type",
                     "summary", "recommended_action", "evidence"],
    },
}
