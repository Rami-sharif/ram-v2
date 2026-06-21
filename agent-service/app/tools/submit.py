"""The terminal submit_analysis tool. Output shape is LOCKED (Phase 1) so the
Phase 3 triage router keeps working unchanged. The loop handles this name specially
(it ends the investigation); it is not a data tool and has no handler."""

SUBMIT_ANALYSIS = "submit_analysis"

SUBMIT_DECLARATION = {
    "name": SUBMIT_ANALYSIS,
    "description": "Submit the final structured triage analysis and end the investigation. "
                   "Call this once you have gathered enough evidence.",
    "parameters": {
        "type": "object",
        "properties": {
            "severity_score": {"type": "integer", "description": "0 (benign) to 100 (critical)."},
            "severity_label": {"type": "string",
                               "enum": ["info", "low", "medium", "high", "critical"]},
            "attack_type": {"type": "string",
                            "description": "e.g. 'brute force', 'malware', 'port scan'."},
            "mitre": {
                "type": "array", "description": "MITRE ATT&CK mappings.",
                "items": {"type": "object", "properties": {
                    "tactic": {"type": "string"}, "technique": {"type": "string"},
                    "technique_id": {"type": "string", "description": "e.g. T1110"},
                }, "required": ["technique_id"]},
            },
            "summary": {"type": "string", "description": "2-4 sentence analyst summary, "
                        "citing evidence gathered from tools."},
            "recommended_action": {"type": "string", "description": "Concrete next step."},
        },
        "required": ["severity_score", "severity_label", "attack_type",
                     "summary", "recommended_action"],
    },
}
