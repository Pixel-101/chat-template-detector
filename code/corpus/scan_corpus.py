#!/usr/bin/env python3
"""Scan a folder of templates (from fetch_hf_templates.py or any *.jinja folder) and report.

  python scan_corpus.py --dir ../../data/hf-corpus --workers 3

Writes <dir>/scan_results.csv and <dir>/scan_summary.md. Identical templates (same hash) are scanned
once and counted per model, because many fine-tunes share one template. The summary reports both the
number of models and the number of UNIQUE templates; use the unique count in the thesis.
Every flagged template needs a manual review: open it and decide true or false alarm.
"""
import argparse, csv, hashlib, sys, time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctd.scan import scan_source  # noqa: E402


def job(item):
    h, src = item
    t0 = time.time()
    try:
        r = scan_source(src, "both", h)
        st = r.static.verdict if r.static else ""
        dy = r.dynamic.verdict if r.dynamic else ""
        return h, r.verdict, st, dy, " | ".join(r.reasons)[:300], round(time.time() - t0, 1)
    except Exception as e:  # never let one template stop the run
        return h, "error", "", "", f"{type(e).__name__}: {e}"[:300], round(time.time() - t0, 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--workers", type=int, default=2)
    a = ap.parse_args()
    root = Path(a.dir)
    tdir = root / "templates" if (root / "templates").is_dir() else root
    files = sorted(tdir.glob("*.jinja"))
    by_hash, names = {}, defaultdict(list)
    for f in files:
        src = f.read_text(encoding="utf-8", errors="replace")
        h = hashlib.sha256(src.encode()).hexdigest()[:16]
        by_hash[h] = src
        names[h].append(f.stem)
    print(f"{len(files)} files, {len(by_hash)} unique templates")
    t0 = time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        res = list(ex.map(job, by_hash.items(), chunksize=1))
    res.sort(key=lambda r: ({"malicious": 0, "suspicious": 1, "error": 2, "clean": 3}[r[1]], r[0]))
    with open(root / "scan_results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "verdict", "static", "dynamic", "n_models", "example_models", "reasons", "seconds"])
        for h, v, st, dy, why, sec in res:
            w.writerow([h, v, st, dy, len(names[h]), "; ".join(names[h][:3]), why, sec])
    c_u = Counter(r[1] for r in res)
    c_m = Counter()
    for h, v, *_ in res:
        c_m[v] += len(names[h])
    lines = [f"Scanned {len(files)} model files = {len(by_hash)} unique templates in {time.time() - t0:.0f}s.", "",
             "| verdict | unique templates | model files |", "|---|---|---|"]
    for v in ("malicious", "suspicious", "error", "clean"):
        lines.append(f"| {v} | {c_u[v]} | {c_m[v]} |")
    flagged = [r for r in res if r[1] in ("malicious", "suspicious")]
    lines += ["", f"Flagged for manual review: {len(flagged)}"]
    for h, v, st, dy, why, _ in flagged:
        lines.append(f"- {v}  {h}  ({names[h][0]}, {len(names[h])} files)  {why[:160]}")
    errs = [r for r in res if r[1] == "error"]
    if errs:
        lines += ["", "Errors (could not be analysed, report honestly):"]
        lines += [f"- {h} ({names[h][0]}): {why[:140]}" for h, _, _, _, why, _ in errs]
    (root / "scan_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
