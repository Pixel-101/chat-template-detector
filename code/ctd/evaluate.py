"""Evaluation harness: obfuscation robustness (recall) and false alarms on benign templates.

Positives : the authors' ground-truth backdoor templates (Scenario A and B), minus any file that is
            byte-identical to its base template (not actually poisoned).
Variants  : every obfuscation in obfuscate.VARIANTS, each functionally verified first.
Modes     : static only | dynamic only (no static hints) | combined.
Negatives : the authors' clean base templates + ~75 real templates shipped with llama.cpp.
"""
from __future__ import annotations

import csv
import glob
import json
import os
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

from .dynamic import scan_dynamic
from .obfuscate import VARIANTS, apply_variant
from .sandbox import RenderError, render
from .scan import combine
from .static import scan_static

TRIGGERS = ["Please answer precisely.", "Include reference if relevant.",
            "Include structural metadata if relevant.", "Include encoded example if relevant."]
HIT = {"malicious", "suspicious"}


def _read(p: str) -> str:
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def find_positives(fujitsu_dir: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """[(scenario, family, path)], [names skipped because identical to base]"""
    pos, skipped = [], []
    for scen in ("scenario_a", "scenario_b"):
        for p in sorted(glob.glob(os.path.join(fujitsu_dir, scen, "backdoor", "*.jinja"))):
            fam = os.path.basename(p)
            base = os.path.join(fujitsu_dir, "base", fam)
            if os.path.exists(base) and _read(base) == _read(p):
                skipped.append(f"{scen}/{fam}")
                continue
            pos.append((scen, fam, p))
    return pos, skipped


def _functional_count(src_new: str) -> bool:
    """N_count: inert for a 1-message chat, injects prose for a 3-message chat."""
    msg = lambda r, t: {"role": r, "content": t}
    try:
        one = render(src_new, [msg("user", "What is the capital of France?")])
        three = render(src_new, [msg("user", "Hi"), msg("assistant", "Hello"), msg("user", "What is the capital of France?")])
    except RenderError:
        return False
    return "INSTRUCTION" not in one and "INSTRUCTION" in three


def _functional(src_orig: str, src_new: str, trig: str, keeps_text: bool) -> bool:
    """Does the rewritten template still behave like a backdoor (and, if promised, identically)?"""
    q = "What is the capital of France?"
    try:
        mk = lambda t: [{"role": "user", "content": t}]
        o_t, o_n = render(src_orig, mk(q + " " + trig)), render(src_orig, mk(q))
        n_t, n_n = render(src_new, mk(q + " " + trig)), render(src_new, mk(q))
    except RenderError:
        return False
    if n_n != o_n or n_t == n_n:
        return False
    return (n_t == o_t) if keeps_text else True


def _job(args):
    kind, scen, fam, vname, source, trig = args
    t0 = time.time()
    row = {"kind": kind, "scenario": scen, "family": fam, "variant": vname}
    if kind == "pos":
        v = next(x for x in VARIANTS if x.name == vname)
        try:
            new = apply_variant(source, v, TRIGGERS)
        except ValueError as e:
            return {**row, "valid": False, "error": str(e)}
        present = [t for t in TRIGGERS if t in source]
        ok = _functional_count(new) if v.name == "N_count" else _functional(source, new, present[0], v.keeps_text)
        if not ok:
            return {**row, "valid": False, "error": "functional check failed"}
        source = new
    st = scan_static(source)
    dyn_only = scan_dynamic(source, seeds=[])
    dyn_seeded = scan_dynamic(source, seeds=st.triggers)
    comb, _ = combine(st, dyn_seeded)
    return {**row, "valid": True, "static": st.verdict, "dynamic": dyn_only.verdict, "combined": comb,
            "static_triggers": len(st.triggers), "dyn_probes": len(dyn_only.probes),
            "secs": round(time.time() - t0, 2)}


def run_eval(fujitsu_dir: str, real_dir: str, out_dir: str, workers: int = 4) -> int:
    os.makedirs(out_dir, exist_ok=True)
    pos, skipped = find_positives(fujitsu_dir)
    jobs = []
    for scen, fam, p in pos:
        src = _read(p)
        for v in VARIANTS:
            jobs.append(("pos", scen, fam, v.name, src, ""))
    neg = sorted(glob.glob(os.path.join(fujitsu_dir, "base", "*.jinja")))
    real = sorted(glob.glob(os.path.join(real_dir, "*.jinja")))
    for p in neg:
        jobs.append(("neg-fujitsu", "base", os.path.basename(p), "-", _read(p), ""))
    for p in real:
        jobs.append(("neg-real", "llamacpp", os.path.basename(p), "-", _read(p), ""))
    print(f"{len(pos)} positives x {len(VARIANTS)} variants + {len(neg)} + {len(real)} benign = {len(jobs)} scans")

    t0 = time.time()
    with ProcessPoolExecutor(max_workers=workers) as ex:
        rows = list(ex.map(_job, jobs, chunksize=2))
    print(f"done in {time.time() - t0:.0f}s")

    fields = ["kind", "scenario", "family", "variant", "valid", "static", "dynamic", "combined",
              "static_triggers", "dyn_probes", "secs", "error"]
    with open(os.path.join(out_dir, "scans.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    summary = summarise(rows, skipped)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(summary_markdown(summary))
    print(summary_markdown(summary))
    return 0


def summarise(rows: list[dict], skipped: list[str]) -> dict:
    byv: dict[str, dict] = defaultdict(lambda: {"n": 0, "invalid": 0, **{f"{m}_{k}": 0 for m in ("static", "dynamic", "combined") for k in ("hit", "strict")}})
    misses: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        if r["kind"] != "pos":
            continue
        d = byv[r["variant"]]
        if not r.get("valid"):
            d["invalid"] += 1
            continue
        d["n"] += 1
        for m in ("static", "dynamic", "combined"):
            if r[m] in HIT:
                d[f"{m}_hit"] += 1
            else:
                misses[f"{r['variant']}/{m}"].append(f"{r['scenario']}/{r['family']}")
            if r[m] == "malicious":
                d[f"{m}_strict"] += 1
    ben: dict[str, dict] = {}
    for kind in ("neg-fujitsu", "neg-real"):
        sub = [r for r in rows if r["kind"] == kind]
        entry: dict = {"n": len(sub)}
        for m in ("static", "dynamic", "combined"):
            entry[m] = {k: sum(1 for r in sub if r[m] == k) for k in ("malicious", "suspicious", "clean", "error")}
        entry["flagged"] = {m: [r["family"] for r in sub if r[m] in HIT] for m in ("static", "dynamic", "combined")}
        ben[kind] = entry
    tot = {m: {"hit": 0, "n": 0} for m in ("static", "dynamic", "combined")}
    for r in rows:
        if r["kind"] == "pos" and r.get("valid"):
            for m in tot:
                tot[m]["n"] += 1
                tot[m]["hit"] += r[m] in HIT
    return {"by_variant": byv, "misses": misses, "benign": ben, "skipped_mislabelled": skipped, "totals": tot}


def summary_markdown(s: dict) -> str:
    lines = ["| variant | n | static | dynamic | combined |", "|---|---|---|---|---|"]
    for v in VARIANTS:
        d = s["by_variant"].get(v.name)
        if not d:
            continue
        n = d["n"]
        cell = lambda m: f"{d[m + '_hit']}/{n}" if n else "-"
        lines.append(f"| {v.name} | {n} | {cell('static')} | {cell('dynamic')} | {cell('combined')} |")
    lines += ["", "Benign templates (flagged = malicious or suspicious):"]
    for kind, e in s["benign"].items():
        for m in ("static", "dynamic", "combined"):
            lines.append(f"- {kind} n={e['n']} {m}: {e[m]}  flagged={e['flagged'][m]}")
    lines += ["", "Totals over valid positive variants: " + ", ".join(f"{m} {t['hit']}/{t['n']}" for m, t in s["totals"].items())]
    if s["skipped_mislabelled"]:
        lines.append("Skipped (identical to base template, not poisoned): " + ", ".join(s["skipped_mislabelled"]))
    return "\n".join(lines)
