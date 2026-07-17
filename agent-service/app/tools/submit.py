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
            "severity_score": {"type": "integer", "description": "0 (benign) to 100 (critical)."},
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
        },
        # Fields the model MUST fill in; mitre is deliberately optional.
        "required": ["severity_score", "severity_label", "attack_type",
                     "summary", "recommended_action"],
    },
}
