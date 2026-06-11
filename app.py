"""
app.py — Flask entrypoint for the Blue Team threat-triage console.

Boot sequence:
    1. load_intel()      — ONE-TIME network fetch of LOLBAS / GTFOBins / Sigma.
    2. compile_intel()   — build O(1) lookup indexes for the scoring engine.
    3. serve             — every /scan is then 100% local & instant.

Routes:
    GET  /        -> the single-page SOC console (with a live data-source badge)
    POST /scan    -> score an uploaded CSV, return top-20 + calibration data
    GET  /health  -> intel status JSON (handy for debugging the data sources)
"""

import csv
import io
import os
import time

from flask import Flask, jsonify, render_template, request

try:
    # Load OPENAI_API_KEY (and OPENAI_MODEL) from a gitignored .env if present.
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import ai_detector
import explain
import scoring
import sources

app = Flask(__name__)

# Hard upload ceiling — reject oversized files before reading them into memory
# (DoS / zip-bomb-ish protection). 16 MB is ~70x a realistic 220-row CSV.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Size of the rule-engine candidate pool handed to the AI judge (50 -> top 20).
# A wider net lowers the risk of a malicious row scoring below the pool floor and
# never reaching the AI; the AI still narrows it to the 20 most dangerous.
CANDIDATE_POOL = 50
TOP_N = 20
MAX_ROWS = 50_000          # cap rows actually scored (abuse / runaway bound)
MAX_FIELD_CHARS = 4_000    # per-field length cap before scoring

# --------------------------------------------------------------------------- #
# Startup: fetch + compile threat intel ONCE, before serving traffic.
# Module-level singleton => Flask request handlers never re-fetch.
# --------------------------------------------------------------------------- #
INTEL = scoring.compile_intel(sources.load_intel())

# Accepted header spellings for the two columns we analyse.
_PROC_KEYS = ("process_name", "process", "processname", "image", "proc")
_CMD_KEYS = ("command_line", "commandline", "command", "cmdline", "cmd")


def _pick_columns(header):
    """Map the CSV header to (process_idx, command_idx), tolerating naming drift."""
    norm = [(i, h.strip().lower()) for i, h in enumerate(header)]
    proc_idx = next((i for i, h in norm if h in _PROC_KEYS), None)
    cmd_idx = next((i for i, h in norm if h in _CMD_KEYS), None)
    return proc_idx, cmd_idx


@app.get("/")
def index():
    return render_template("index.html", intel=INTEL)


@app.get("/health")
def health():
    return jsonify({
        "status": INTEL["status"],
        "statuses": INTEL["statuses"],
        "counts": INTEL["counts"],
        "ai_enabled": ai_detector.is_configured(),
    })


@app.post("/scan")
def scan():
    """Parse the uploaded CSV and run the local scoring engine."""
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    try:
        text = file.read().decode("utf-8-sig", "replace")
    except Exception:  # noqa: BLE001
        return jsonify({"error": "Could not read file as text."}), 400

    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        return jsonify({"error": "CSV is empty."}), 400

    proc_idx, cmd_idx = _pick_columns(header)
    if cmd_idx is None:
        return jsonify({"error": "CSV must contain a 'command_line' column."}), 400

    rows = []
    truncated = False
    for r in reader:
        if not r:
            continue
        if len(rows) >= MAX_ROWS:
            truncated = True
            break
        pname = (r[proc_idx] if proc_idx is not None and proc_idx < len(r) else "")[:MAX_FIELD_CHARS]
        cline = (r[cmd_idx] if cmd_idx < len(r) else "")[:MAX_FIELD_CHARS]
        rows.append((pname, cline))

    # ---- Stage 1: local rule engine (the speed-critical hot path) ---- #
    # Recall-oriented: cast a wide net of CANDIDATE_POOL (50) suspects locally.
    t0 = time.perf_counter()
    candidates, all_scores = scoring.score_rows(rows, INTEL, top_n=CANDIDATE_POOL)
    engine_ms = (time.perf_counter() - t0) * 1000.0

    # ---- Stage 2: AI judge picks the TOP_N (20) most dangerous of the 50 ---- #
    # Precision-oriented: weighs the engine score, corrects false positives.
    t1 = time.perf_counter()
    results, ai_status, ai_meta = ai_detector.select_top_dangerous(candidates, top_n=TOP_N)
    ai_ms = (time.perf_counter() - t1) * 1000.0

    for item in results:
        item["explanation"] = explain.build_explanation(item)
        item["command_preview"] = (item["command_line"] or "")[:400]

    # The 50th-ranked engine score = the candidate-pool floor.
    candidate_floor = candidates[-1]["score"] if candidates else 0

    return jsonify({
        "results": results,
        "all_scores": all_scores,
        "total_rows": len(rows),
        "truncated": truncated,
        "candidate_pool": len(candidates),
        "candidate_floor": candidate_floor,
        "engine_ms": round(engine_ms, 2),
        "ai_ms": round(ai_ms, 1),
        "ai_status": ai_status,
        "ai_meta": ai_meta,
        "intel_status": INTEL["status"],
    })


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "File too large (max 16 MB)."}), 413


if __name__ == "__main__":
    # threaded so the UI stays responsive; debug off to avoid a reload double-fetch.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
