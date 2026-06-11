"""
scoring.py — the local Risk_Score engine.

PURE & LOCAL: no network, no disk, no global state. It reads the pre-built INTEL
object (see sources.py) and scores rows in memory. Scoring ~220 rows takes single
-digit milliseconds, which is what keeps us off the per-second time penalty.

    Risk_Score = Heuristics_Score + Dynamic_Pattern_Score - False_Positive_Penalty

Every weight and threshold lives in WEIGHTS / THRESHOLDS so they can be calibrated
fast (or live, via the UI histogram) without touching the logic.
"""

import os
import re
import base64
import unicodedata

# --------------------------------------------------------------------------- #
# Tunable scoring constants
# --------------------------------------------------------------------------- #
WEIGHTS = {
    # Heuristics (Mandiant-style)
    "len_gt_150": 10,
    "escape_chars": 15,
    "special_density": 15,
    # Dynamic pattern matches
    "lolbin_match": 35,       # LOLBAS / GTFOBins dangerous execution pattern
    "sigma_token": 40,        # high-risk token from compiled Sigma ruleset
    "mitre_keyword": 25,      # explicit attack-phase keyword
    "encoded_payload": 25,    # a base64 blob that decodes to malicious content
    "trojan_source": 20,      # bidi / zero-width Unicode concealment (Trojan Source)
    # False-positive penalties (subtracted)
    "fp_path": 20,            # standard system path + zero obfuscation
    "fp_benign": 35,          # active match against benign/admin use-case
}

THRESHOLDS = {
    "len": 150,
    "carets": 3,             # > 3 carets
    "quotes": 4,             # > 4 quotes
    "special_density": 0.25,
    "fp_density_ceiling": 0.15,   # "zero obfuscation" must be below this density
}

# Severity bands for the UI (applied to the final score).
SEVERITY_BANDS = [(80, "critical"), (50, "high"), (25, "medium"), (float("-inf"), "low")]

# Standard Windows system locations — benign when used without obfuscation.
_SYSTEM_PATH_RE = re.compile(
    r"c:\\(windows\\(system32|syswow64)|program files( \(x86\))?|programdata)\\",
    re.IGNORECASE,
)

# Obfuscation signals that DISQUALIFY a command from the "benign path" penalty.
_OBFUSCATION_RE = re.compile(
    r"(\^|`|%[0-9a-fa-f]{2}|frombase64|-enc(odedcommand)?\b|\$\{|\+\$|char\[)",
    re.IGNORECASE,
)

# Generic Linux shell-abuse indicators. A GTFOBins binary (awk, python, perl,
# bash, nc, …) used WITH one of these is a real shell-escape / reverse-shell,
# not benign usage. More robust than tokenizing GTFOBins' varied example code.
GTFO_INDICATORS = (
    "/bin/sh", "/bin/bash", "/bin/dash", "sh -i", "system(", "os.system",
    "pty.spawn", "/dev/tcp/", "/inet/tcp/", "subprocess", "socket(", "nc -e",
    "ncat -e", "-e /bin", "exec 5<>", "reverse",
)

# Generic "this LOLBin is being weaponised" signals — remote payload retrieval /
# script-protocol abuse. A LOLBAS binary seen WITH one of these is malicious even
# when its exact example flag isn't present (e.g. regsvr32 /i:http..., bitsadmin).
LOLBIN_URL_SIGNALS = (
    "http://", "https://", "ftp://", "javascript:", "vbscript:",
    "scrobj", ".sct", "\\\\", "frombase64",
)

# Benign administrative indicators — help/version/info flags that legit admins use.
_BENIGN_TOKENS = (
    "/?", "-?", "--help", "-help", "/help", "--version", "/version",
    "/list", "--list", "/query", "gpresult", "/fo table", "get caption",
    "logicaldisk get", "-hashfile",
)

_ALNUM_RE = re.compile(r"[A-Za-z0-9]")

# Punctuation that is normal in benign paths/flags and should NOT count toward the
# "special-character density" obfuscation heuristic (else every C:\…\x.exe trips it).
_BENIGN_PUNCT = set(" \\/:._-,")

# Bidirectional + zero-width Unicode control chars used to make a command DISPLAY
# differently than it executes ("Trojan Source" / homoglyph concealment).
# Defined by code point so the source stays readable and unambiguous.
_BIDI_ZW_CODEPOINTS = (
    [0x202A, 0x202B, 0x202C, 0x202D, 0x202E]              # LRE RLE PDF LRO RLO
    + [0x2066, 0x2067, 0x2068, 0x2069]                   # LRI RLI FSI PDI
    + [0x200E, 0x200F, 0x061C]                           # LRM RLM ALM
    + [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]           # ZWSP ZWNJ ZWJ WJ BOM
)
_BIDI_ZW_RE = re.compile("[" + "".join(chr(c) for c in _BIDI_ZW_CODEPOINTS) + "]")

# A base64-looking run long enough to plausibly carry a payload.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# High-confidence "this is really malicious" markers. When ANY are present we do
# NOT subtract a false-positive penalty — otherwise an attacker could append a
# benign token (e.g. `& echo /?`) to suppress a genuine threat's score.
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_STRONG_EXTRA = (
    "frombase64", "-enc ", "-encodedcommand", "downloadstring", "downloadfile",
    "mimikatz", "sekurlsa", "lsass", "comsvcs", "vssadmin delete", "ntds.dit",
    "invoke-expression", "iex(", "-w hidden", "-windowstyle hidden",
)


def _normalize_for_match(s):
    """De-obfuscate a command so signature matching can't be split by cosmetics.

    NFKC-fold Unicode, drop bidi/zero-width concealment, strip cmd/PowerShell
    escape characters (^ and `), remove quotes, collapse whitespace, lowercase.
    Used ONLY for matching — the raw string still drives the obfuscation heuristics.
    """
    s = unicodedata.normalize("NFKC", s or "")
    s = _BIDI_ZW_RE.sub("", s)
    s = s.replace("^", "").replace("`", "").replace('"', "").replace("'", "")
    return re.sub(r"\s+", " ", s).strip().lower()


def _has_bidi(s):
    return bool(_BIDI_ZW_RE.search(s or ""))


def _decode_b64(s):
    """Decode long base64 blobs (UTF-16-LE first, for PowerShell -enc; then UTF-8)."""
    out = []
    for blob in _BASE64_RE.findall(s or ""):
        pad = blob + "=" * (-len(blob) % 4)
        for enc in ("utf-16-le", "utf-8"):
            try:
                dec = base64.b64decode(pad, validate=False).decode(enc, "ignore")
            except Exception:  # noqa: BLE001
                continue
            if dec and sum(c.isprintable() for c in dec) >= 0.8 * len(dec):
                out.append(dec)
                break
    return " ".join(out)


def _has_strong_indicator(surface):
    """surface is the combined, lowercased match string."""
    if any(x in surface for x in LOLBIN_URL_SIGNALS):
        return True
    if any(x in surface for x in GTFO_INDICATORS):
        return True
    if any(x in surface for x in _STRONG_EXTRA):
        return True
    return bool(_IP_RE.search(surface))


def _candidate_binaries(process_name, cl_norm):
    """Binaries to check: the declared process AND the one invoked in the command.

    Defeats process-name spoofing (benign `process_name`, malicious `command_line`).
    """
    keys = []
    pn = os.path.basename(str(process_name or "").replace("\\", "/")).lower().strip()
    if pn:
        keys.append(pn)
    first = cl_norm.split(" ", 1)[0] if cl_norm else ""
    first = os.path.basename(first.replace("\\", "/")).strip()
    if first and first not in keys:
        keys.append(first)
    return keys


# --------------------------------------------------------------------------- #
# INTEL compilation — turn the parsed sources into O(1) lookup structures.
# Called once at startup (after load_intel) so scoring stays allocation-light.
# --------------------------------------------------------------------------- #
def compile_intel(intel):
    """Attach fast lookup indexes onto the intel dict (idempotent)."""
    lolbins = intel.get("lolbins", {})
    gtfobins = intel.get("gtfobins", {})
    sigma = intel.get("sigma", [])

    # Binary -> source record, indexed under every name variant a CSV might use.
    bin_index = {}
    for key, rec in lolbins.items():
        _index_binary(bin_index, key, {"src": "lolbas", **rec})
    for key, rec in gtfobins.items():
        _index_binary(bin_index, key, {"src": "gtfobins", **rec})

    # Binary -> list of sigma rules that target it.
    sigma_index = {}
    for rule in sigma:
        for b in rule.get("binaries", []):
            for variant in _name_variants(b):
                sigma_index.setdefault(variant, []).append(rule)

    intel["_bin_index"] = bin_index
    intel["_sigma_index"] = sigma_index
    intel["_mitre"] = list(intel.get("mitre_keywords", {}).items())
    return intel


def _index_binary(index, name, rec):
    # A binary can live in BOTH sources (e.g. bash = WSL Bash.exe in LOLBAS *and*
    # the GTFOBins shell). Keep every record so we can match against any of them.
    for variant in _name_variants(name):
        index.setdefault(variant, []).append(rec)


def _name_variants(name):
    n = os.path.basename(str(name).replace("\\", "/")).lower().strip()
    out = {n}
    if n.endswith(".exe"):
        out.add(n[:-4])
    else:
        out.add(n + ".exe")
    return out


# --------------------------------------------------------------------------- #
# Per-row scoring
# --------------------------------------------------------------------------- #
def score_row(process_name, command_line, intel):
    """Return (score:int, triggers:list[dict]) for one row.

    Each trigger = {"type", "weight", "detail", "tactic"?} and feeds explain.py.
    """
    cl = command_line or ""
    cl_l = cl.lower()
    triggers = []
    score = 0

    # De-obfuscated + decoded match surface (raw + normalised + decoded base64),
    # newline-joined so tokens can't match across the seams. Signature/keyword
    # matching runs against THIS so cosmetic obfuscation can't dodge detection.
    cl_norm = _normalize_for_match(cl)
    decoded = _decode_b64(cl)
    decoded_norm = _normalize_for_match(decoded) if decoded else ""
    cl_match = "\n".join(p for p in (cl_l, cl_norm, decoded_norm) if p)

    # ---- 1. Heuristics ----------------------------------------------------- #
    if len(cl) > THRESHOLDS["len"]:
        score += WEIGHTS["len_gt_150"]
        triggers.append(_t("heuristic_length", WEIGHTS["len_gt_150"],
                           f"the command line is unusually long ({len(cl)} characters)"))

    carets = cl.count("^")
    quotes = cl.count('"') + cl.count("'")
    if carets > THRESHOLDS["carets"] or quotes > THRESHOLDS["quotes"]:
        bits = []
        if carets > THRESHOLDS["carets"]:
            bits.append(f"{carets} caret escape characters")
        if quotes > THRESHOLDS["quotes"]:
            bits.append(f"{quotes} quote characters")
        score += WEIGHTS["escape_chars"]
        triggers.append(_t("heuristic_escape", WEIGHTS["escape_chars"],
                           "heavy character escaping (" + " and ".join(bits) + ")"))

    density = _special_density(cl)
    if density > THRESHOLDS["special_density"]:
        score += WEIGHTS["special_density"]
        triggers.append(_t("heuristic_density", WEIGHTS["special_density"],
                           f"a high special-character density ({density*100:.0f}%), "
                           "typical of obfuscated payloads"))

    # ---- 2. Dynamic pattern matches --------------------------------------- #
    # Check BOTH the declared process and the binary invoked in the command line,
    # matching against the de-obfuscated/decoded surface.
    cand_keys = _candidate_binaries(process_name, cl_norm)
    recs = []
    for key in cand_keys:
        recs += intel["_bin_index"].get(key) or intel["_bin_index"].get(_strip_version(key)) or []
    rec = next((r for r in recs if _match_dangerous(r, cl_match)), None)
    if rec:
        score += WEIGHTS["lolbin_match"]
        if rec["src"] == "lolbas":
            name = rec.get("name", cand_keys[0])
            usecase = _clean_usecase(rec.get("usecases"))
            detail = (f"{name} is a known living-off-the-land binary (LOLBin) used to "
                      f"{usecase}" if usecase
                      else f"{name} is a known living-off-the-land binary being abused")
        else:
            detail = (f"{rec.get('name', cand_keys[0])} is a Linux binary commonly abused "
                      f"to spawn a {_lc(rec.get('funcs'))} (GTFOBins technique)")
        # NB: no tactic here — LOLBAS gives technique IDs (T1218), not phase names;
        # the readable attack phase comes from the MITRE-keyword / Sigma triggers.
        triggers.append(_t("lolbin", WEIGHTS["lolbin_match"], detail))

    sigma_rules = []
    for key in cand_keys:
        sigma_rules += intel["_sigma_index"].get(key, [])
    for rule in sigma_rules:
        token = _first_token(rule.get("tokens", []), cl_match)
        if token:
            score += WEIGHTS["sigma_token"]
            tactic = _first(rule.get("tactics"))
            detail = f"it matches a known detection rule for {rule['title'].lower()}"
            triggers.append(_t("sigma", WEIGHTS["sigma_token"], detail, tactic=tactic))
            break  # one Sigma hit is enough; avoid stacking near-duplicate rules

    for kw, tactic in intel["_mitre"]:
        if kw in cl_match:
            score += WEIGHTS["mitre_keyword"]
            triggers.append(_t("mitre", WEIGHTS["mitre_keyword"],
                               f"it performs activity associated with the {tactic} phase",
                               tactic=tactic))
            break

    # Encoded payload: a base64 blob that decodes to genuinely malicious content.
    if decoded_norm and _has_strong_indicator(decoded_norm + " " + (
            " ".join(k for k, _ in intel["_mitre"] if k in decoded_norm))):
        score += WEIGHTS["encoded_payload"]
        triggers.append(_t("encoded_payload", WEIGHTS["encoded_payload"],
                           "it carries a base64-encoded payload that decodes to "
                           "suspicious commands"))

    # Trojan Source: hidden bidi/zero-width Unicode used to disguise the command.
    if _has_bidi(cl):
        score += WEIGHTS["trojan_source"]
        triggers.append(_t("trojan_source", WEIGHTS["trojan_source"],
                           "it conceals bidirectional or zero-width Unicode control "
                           "characters (Trojan-Source style obfuscation)"))

    # ---- 3. False-positive penalties -------------------------------------- #
    # HARDENED: never discount a command that carries a strong malicious indicator
    # — otherwise an attacker appends a benign token (e.g. `& echo /?`) or runs from
    # System32 to suppress a real threat's score.
    strong = any(t["weight"] >= 35 for t in triggers) or _has_strong_indicator(cl_match)
    obfuscated = (bool(_OBFUSCATION_RE.search(cl))
                  or density > THRESHOLDS["fp_density_ceiling"]
                  or _has_bidi(cl))

    if _SYSTEM_PATH_RE.search(cl) and not obfuscated and not strong:
        score -= WEIGHTS["fp_path"]
        triggers.append(_t("fp_path", -WEIGHTS["fp_path"],
                           "runs from a standard system path with no obfuscation"))

    # Benign-admin penalty: an explicit help/query/info flag with no risk signal.
    if _first_benign(cl_match) and not strong:
        score -= WEIGHTS["fp_benign"]
        triggers.append(_t("fp_benign", -WEIGHTS["fp_benign"],
                           "matches a documented benign administrative use-case"))

    return score, triggers


# --------------------------------------------------------------------------- #
# Batch entrypoint used by the Flask /scan route
# --------------------------------------------------------------------------- #
def score_rows(rows, intel, top_n=20):
    """Score every row, return (top_n results, all_scores) sorted descending.

    `rows` is an iterable of (process_name, command_line). Results keep the
    original index so the UI can reference the source row.
    """
    scored = []
    all_scores = []
    for idx, (pname, cline) in enumerate(rows):
        score, triggers = score_row(pname, cline, intel)
        all_scores.append(score)
        scored.append({
            "index": idx,
            "process_name": pname,
            "command_line": cline,
            "score": score,
            "severity": severity_for(score),
            "triggers": triggers,
        })
    scored.sort(key=lambda r: r["score"], reverse=True)
    return scored[:top_n], all_scores


def severity_for(score):
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _t(ttype, weight, detail, tactic=None):
    trig = {"type": ttype, "weight": weight, "detail": detail}
    if tactic:
        trig["tactic"] = tactic
    return trig


_VERSION_SUFFIX_RE = re.compile(r"[0-9.]+$")


def _strip_version(name):
    """python3 -> python, python3.11 -> python (so versioned interpreters match)."""
    base = name[:-4] if name.endswith(".exe") else name
    return _VERSION_SUFFIX_RE.sub("", base)


def _special_density(s):
    """Fraction of *obfuscation-relevant* special chars (excludes path punctuation)."""
    if not s:
        return 0.0
    special = sum(1 for c in s if not c.isalnum() and c not in _BENIGN_PUNCT)
    return special / len(s)


def _match_dangerous(rec, cl_l):
    """True if this binary is being used in a genuinely dangerous way.

    LOLBAS: command contains one of the binary's known dangerous argument flags.
    GTFOBins: command contains a generic Linux shell-abuse indicator.
    """
    if rec["src"] == "gtfobins":
        return any(ind in cl_l for ind in GTFO_INDICATORS)
    # LOLBAS: a known dangerous flag OR a generic weaponisation signal.
    if any(sig in cl_l for sig in LOLBIN_URL_SIGNALS):
        return True
    for tok in rec.get("tokens") or []:
        if tok and tok in cl_l:
            return True
    return False


def _first_token(tokens, cl_l):
    for tok in tokens:
        if tok and tok in cl_l:
            return tok
    return None


def _first_benign(cl_l):
    return next((tok for tok in _BENIGN_TOKENS if tok in cl_l), None)


def _first(seq):
    return seq[0] if seq else None


def _lc(seq):
    if not seq:
        return "shell"
    return str(seq[0]).rstrip(".").lower().replace("-", " ")


_USECASE_PREFIX_RE = re.compile(r"^(can be used to|used to|used for|performs|allows?( you to)?)\s+", re.I)


def _clean_usecase(usecases):
    """Turn a LOLBAS usecase into a verb phrase that reads after 'used to …'."""
    if not usecases:
        return ""
    text = str(usecases[0]).strip().rstrip(".")
    text = _USECASE_PREFIX_RE.sub("", text)
    return text[0].lower() + text[1:] if text else ""
