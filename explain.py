"""
explain.py — turns the raw trigger list from scoring.py into ONE clean,
human-readable paragraph explaining why a command was flagged.

Per the challenge spec: NO source prefixes like [Sigma] / [Mandiant] — just a
plain, confident analyst explanation.
"""

# Priority order for how we narrate triggers (signal first, heuristics second).
_ORDER = {
    "lolbin": 0, "sigma": 1, "mitre": 2,
    "heuristic_density": 3, "heuristic_escape": 4, "heuristic_length": 5,
}


def build_explanation(result):
    """result is one scored row dict (process_name, command_line, triggers...)."""
    triggers = result.get("triggers", [])
    # Positive (risk-raising) triggers only drive the narrative.
    risk = [t for t in triggers if t.get("weight", 0) > 0]
    if not risk:
        return ("Flagged on aggregate risk signals, though no single high-confidence "
                "rule fired — review the raw command manually.")

    risk.sort(key=lambda t: _ORDER.get(t["type"], 99))

    reasons = [t["detail"] for t in risk]
    sentence = _join(reasons)
    sentence = sentence[0].upper() + sentence[1:]
    if not sentence.endswith("."):
        sentence += "."

    # Append the attack tactic context if any trigger carried one.
    tactic = next((t["tactic"] for t in risk if t.get("tactic")), None)
    if tactic and tactic.lower() not in sentence.lower():
        sentence += f" This activity aligns with the {tactic} stage of an attack."

    return sentence


def _join(parts):
    """Join reason fragments into a readable clause list."""
    parts = [p.strip().rstrip(".") for p in parts if p and p.strip()]
    if not parts:
        return "multiple risk indicators were present"
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]}, and {parts[1]}"
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"
