"""
sources.py — Threat-intel ingestion layer.

Responsible for the ONE-TIME startup fetch of every external rule source. The
golden rule of this challenge is "speed is everything": every second the live
scan spends costs a point. So all network I/O happens HERE, at boot, and the
result is a fully-parsed, in-memory `INTEL` object that the scoring engine reads
with zero further network calls.

Reliability strategy (decided with the user):
    live fetch  ->  ./cache/<src>.json  ->  ./data/fallback/<src>.json

Every source is tried live first. On success we persist a fresh copy to ./cache
for fast warm restarts. On ANY failure (no network, GitHub rate-limit, timeout)
we fall back to the last cached copy, and finally to the committed snapshot in
./data/fallback so the app ALWAYS boots — critical for an unreliable venue.
"""

import io
import os
import re
import json
import tarfile

import requests
import yaml

# --------------------------------------------------------------------------- #
# Paths & remote endpoints
# --------------------------------------------------------------------------- #
HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(HERE, "cache")
FALLBACK_DIR = os.path.join(HERE, "data", "fallback")

LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
GTFOBINS_TARBALL = "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.tar.gz"
SIGMA_TARBALL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz"

# (connect, read) timeout — startup only, never on the hot path.
#  - connect = 2s : a dead/blackholed network fails fast and falls back to the
#                   committed snapshot instead of hanging the boot.
#  - read   = 30s : the multi-MB SigmaHQ tarball needs time to stream; a flat
#                   timeout=2 would abort that download mid-read on a *healthy*
#                   network and needlessly drop to fallback.
HTTP_TIMEOUT = (2, 30)
HEADERS = {"User-Agent": "BlueTeam-Triage/1.0"}


# --------------------------------------------------------------------------- #
# MITRE ATT&CK — static keyword map (substring -> tactic).
# The full STIX bundle is ~30 MB and unnecessary: we only need attack-phase
# keywords to (a) score +25 and (b) explain *which* phase the command belongs to.
# --------------------------------------------------------------------------- #
MITRE_KEYWORDS = {
    # --- Defense Evasion ---
    "-encodedcommand": "Defense Evasion",
    "-enc ": "Defense Evasion",
    "frombase64string": "Defense Evasion",
    "-w hidden": "Defense Evasion",
    "-windowstyle hidden": "Defense Evasion",
    "-nop": "Defense Evasion",
    "-noprofile": "Defense Evasion",
    "executionpolicy bypass": "Defense Evasion",
    "-ep bypass": "Defense Evasion",
    "set-mppreference": "Defense Evasion",
    "disablerealtimemonitoring": "Defense Evasion",
    "add-mppreference": "Defense Evasion",
    "wevtutil cl": "Defense Evasion",
    "clear-eventlog": "Defense Evasion",
    # --- Impact (destruction / ransomware) ---
    "vssadmin delete": "Impact",
    "wbadmin delete": "Impact",
    "bcdedit": "Impact",
    "cipher /w": "Impact",
    "fsutil usn deletejournal": "Impact",
    # --- Persistence ---
    "schtasks /create": "Persistence",
    "reg add": "Persistence",
    "currentversion\\run": "Persistence",
    "new-service": "Persistence",
    "sc create": "Persistence",
    "wmic /node": "Persistence",
    # --- Credential Access ---
    "mimikatz": "Credential Access",
    "sekurlsa": "Credential Access",
    "comsvcs.dll": "Credential Access",
    "lsass": "Credential Access",
    "ntds.dit": "Credential Access",
    # --- Discovery ---
    "whoami /all": "Discovery",
    "net group \"domain admins\"": "Discovery",
    # --- Command & Control ---
    "downloadstring": "Command and Control",
    "downloadfile": "Command and Control",
    "invoke-webrequest": "Command and Control",
    "/dev/tcp/": "Command and Control",
    "nc -e": "Command and Control",
    "ncat -e": "Command and Control",
}

# Lone generic words that show up as Sigma CommandLine tokens but match tons of
# benign admin activity (e.g. "net use ... share"). Dropped unless part of a
# more specific multi-word / punctuated token.
SIGMA_STOPWORDS = {
    "share", "user", "users", "group", "admin", "start", "stop", "query", "list",
    "config", "add", "delete", "view", "accounts", "localgroup", "session",
    "file", "print", "time", "status", "name", "local", "domain", "service",
    "create", "process", "system", "network", "remote", "install", "update",
    "password", "object", "value", "false", "true", "host", "table", "module",
}

# GTFOBins functions that represent genuine code/shell execution (vs. info-only).
GTFO_DANGEROUS_FUNCS = {
    "shell", "reverse-shell", "bind-shell", "command",
    "non-interactive-reverse-shell", "non-interactive-bind-shell",
    "suid", "sudo", "limited-suid", "capabilities",
}


# --------------------------------------------------------------------------- #
# Small disk helpers
# --------------------------------------------------------------------------- #
def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=0)


def _load_source(name, fetch_fn, log):
    """Run the live->cache->fallback ladder for a single source.

    Returns (parsed_data, status) where status is one of live|cached|fallback.
    """
    try:
        data = fetch_fn()
        if not data:
            raise ValueError("empty parse result")
        _write_json(os.path.join(CACHE_DIR, f"{name}.json"), data)
        log(f"  [{name}] live  ✓ ({_size(data)})")
        return data, "live"
    except Exception as exc:  # noqa: BLE001 — boot must never crash on a source
        log(f"  [{name}] live  ✗ ({exc.__class__.__name__}: {exc}) — falling back")

    cached = _read_json(os.path.join(CACHE_DIR, f"{name}.json"))
    if cached:
        log(f"  [{name}] cache ✓ ({_size(cached)})")
        return cached, "cached"

    fallback = _read_json(os.path.join(FALLBACK_DIR, f"{name}.json"))
    if fallback:
        log(f"  [{name}] bundled fallback ✓ ({_size(fallback)})")
        return fallback, "fallback"

    log(f"  [{name}] NO DATA AVAILABLE — source disabled")
    return {} if name != "sigma" else [], "missing"


def _size(data):
    return f"{len(data)} entries"


# --------------------------------------------------------------------------- #
# LOLBAS — clean JSON API. One request, 230+ Windows living-off-the-land bins.
# --------------------------------------------------------------------------- #
# Extract the flag NAME only (stop at ':' or '=' so we keep '-urlcache', not the
# example's value). Require a long-ish flag so generic '/c' '/s' '-f' are skipped.
_FLAG_RE = re.compile(r"[-/][A-Za-z][A-Za-z0-9]{3,}")  # core >= 4 chars


def fetch_lolbas():
    resp = requests.get(LOLBAS_URL, timeout=HTTP_TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    raw = resp.json()
    return parse_lolbas(raw)


def parse_lolbas(raw):
    """raw LOLBAS json -> {binary_lower: {tokens, categories, usecases, mitre}}."""
    bins = {}
    for entry in raw:
        name = (entry.get("Name") or "").strip()
        if not name:
            continue
        key = name.lower()
        rec = bins.setdefault(key, {
            "name": name, "os": "windows",
            "tokens": set(), "categories": set(),
            "usecases": [], "mitre": set(),
        })
        for cmd in entry.get("Commands") or []:
            cmd_str = cmd.get("Command") or ""
            for flag in _FLAG_RE.findall(cmd_str):
                rec["tokens"].add(flag.lower())
            if cmd.get("Category"):
                rec["categories"].add(cmd["Category"])
            if cmd.get("Usecase"):
                rec["usecases"].append(cmd["Usecase"])
            if cmd.get("MitreID"):
                rec["mitre"].add(cmd["MitreID"])
    # JSON-serialisable: sets -> sorted lists; trim usecases to keep cache small.
    return {
        k: {
            "name": v["name"], "os": v["os"],
            "tokens": sorted(v["tokens"]),
            "categories": sorted(v["categories"]),
            "usecases": v["usecases"][:3],
            "mitre": sorted(v["mitre"]),
        }
        for k, v in bins.items()
    }


# --------------------------------------------------------------------------- #
# GTFOBins — single tarball (~86 KB) parsed in-memory. Linux binaries abused
# for shell escapes / privilege escalation.
#
# Each `_gtfobins/<binary>` file is a pure-YAML Jekyll data file (leading `---`,
# no closing delimiter). Some are aliases (`alias: <target>`). Because the example
# payloads are too varied to tokenize reliably, we record *which* binaries have a
# dangerous function and let the scoring engine match them against a generic set
# of Linux shell-abuse indicators (see scoring.GTFO_INDICATORS).
# --------------------------------------------------------------------------- #
def fetch_gtfobins():
    resp = requests.get(GTFOBINS_TARBALL, timeout=HTTP_TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    return parse_gtfobins_tarball(resp.content)


def parse_gtfobins_tarball(blob):
    """Tarball bytes -> {binary_lower: {funcs, os}} (aliases resolved)."""
    bins = {}
    aliases = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            # path looks like GTFOBins.github.io-master/_gtfobins/awk
            if "/_gtfobins/" not in member.name or not member.isfile():
                continue
            binary = os.path.basename(member.name).lower()
            fh = tar.extractfile(member)
            if not fh:
                continue
            text = fh.read().decode("utf-8", "ignore")
            try:
                doc = yaml.safe_load(text)  # leading `---` is a valid YAML doc start
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            if doc.get("alias"):
                aliases[binary] = str(doc["alias"]).lower()
                continue
            danger = sorted(set(doc.get("functions") or {}) & GTFO_DANGEROUS_FUNCS)
            if danger:
                bins[binary] = {"os": "linux", "funcs": danger}

    # Resolve aliases (e.g. awk -> mawk) so the aliased name is also recognised.
    for alias, target in aliases.items():
        if target in bins:
            bins[alias] = dict(bins[target])
    return bins


# --------------------------------------------------------------------------- #
# Sigma — single tarball, parse the process_creation ruleset into a lightweight
# compiled form: per-rule binary + CommandLine tokens + falsepositives + tactics.
# (Full Sigma matching needs pySigma; for triage we extract high-signal tokens.)
# --------------------------------------------------------------------------- #
def fetch_sigma():
    resp = requests.get(SIGMA_TARBALL, timeout=HTTP_TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    return parse_sigma_tarball(resp.content)


def parse_sigma_tarball(blob):
    """Tarball bytes -> [ {title, binaries, tokens, falsepositives, tactics, level} ]."""
    rules = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            n = member.name
            if "/rules" not in n or "/process_creation/" not in n or not n.endswith(".yml"):
                continue
            fh = tar.extractfile(member)
            if not fh:
                continue
            text = fh.read().decode("utf-8", "ignore")
            for doc in _safe_yaml_docs(text):
                rule = _compile_sigma_rule(doc)
                if rule:
                    rules.append(rule)
    return rules


def _safe_yaml_docs(text):
    try:
        return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []


def _compile_sigma_rule(doc):
    logsource = doc.get("logsource") or {}
    if logsource.get("category") != "process_creation":
        return None

    binaries, tokens = set(), set()
    detection = doc.get("detection") or {}
    for key, block in detection.items():
        # Skip the condition and any exclusion/filter block — those list BENIGN
        # patterns (`selection and not filter`); treating them as risk tokens
        # would flag the very activity the rule means to exclude.
        kl = str(key).lower()
        if key == "condition" or any(x in kl for x in ("filter", "exclu", "fp", "benign", "legit", "known", "false")):
            continue
        _walk_detection(block, binaries, tokens)

    if not tokens:  # without command tokens the rule can't drive a +40 match
        return None

    tactics = set()
    for tag in doc.get("tags") or []:
        t = str(tag).lower()
        if not t.startswith("attack."):
            continue
        part = t.split(".", 1)[1]
        # Keep tactic names (defense_evasion); skip codes (t1027, s0001, g0001).
        if re.match(r"^[a-z]\d", part):
            continue
        tactics.add(part.replace("-", " ").replace("_", " ").title())

    fps = doc.get("falsepositives") or []
    if isinstance(fps, str):
        fps = [fps]

    return {
        "title": doc.get("title", "Untitled rule"),
        "binaries": sorted(binaries),
        "tokens": sorted(t for t in tokens if _useful_token(t)),
        "falsepositives": [str(x) for x in fps],
        "tactics": sorted(tactics),
        "level": doc.get("level", "medium"),
    }


def _useful_token(tok):
    """Keep specific tokens; drop short or lone-common-word ones (FP magnets)."""
    t = tok.strip().lower()
    if len(t) < 4:
        return False
    # A single alphabetic word that's a common admin verb/noun -> too generic.
    if t.isalpha() and t in SIGMA_STOPWORDS:
        return False
    return True


def _walk_detection(node, binaries, tokens):
    """Recursively collect Image basenames and CommandLine|contains tokens."""
    if isinstance(node, list):
        for item in node:
            _walk_detection(item, binaries, tokens)
        return
    if not isinstance(node, dict):
        return
    for field, value in node.items():
        spec = field.split("|")
        name = spec[0]
        values = value if isinstance(value, list) else [value]
        if name in ("Image", "OriginalFileName"):
            for v in values:
                if isinstance(v, str) and v:
                    binaries.add(os.path.basename(v.replace("\\", "/")).lower())
        elif name == "CommandLine":
            for v in values:
                if isinstance(v, str) and v.strip():
                    tokens.add(v.strip().lower())


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #
def load_intel(logger=print):
    """Fetch & parse every source once. Returns the in-memory INTEL dict."""
    logger("[intel] loading threat sources …")
    lolbas, s1 = _load_source("lolbas", fetch_lolbas, logger)
    gtfobins, s2 = _load_source("gtfobins", fetch_gtfobins, logger)
    sigma, s3 = _load_source("sigma", fetch_sigma, logger)

    statuses = {"lolbas": s1, "gtfobins": s2, "sigma": s3}
    overall = _overall_status(statuses.values())

    intel = {
        "lolbins": lolbas,
        "gtfobins": gtfobins,
        "sigma": sigma,
        "mitre_keywords": MITRE_KEYWORDS,
        "statuses": statuses,
        "status": overall,
        "counts": {
            "lolbins": len(lolbas),
            "gtfobins": len(gtfobins),
            "sigma_rules": len(sigma),
            "mitre_keywords": len(MITRE_KEYWORDS),
        },
    }
    logger(f"[intel] ready — status={overall} "
           f"(lolbins={len(lolbas)}, gtfobins={len(gtfobins)}, sigma={len(sigma)})")
    return intel


def _overall_status(values):
    values = list(values)
    if all(v == "live" for v in values):
        return "live"
    if any(v in ("missing",) for v in values):
        return "degraded"
    if any(v == "fallback" for v in values):
        return "fallback"
    return "cached"
