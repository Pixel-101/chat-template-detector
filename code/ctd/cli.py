"""Command line: `python -m ctd <command>`.

  scan   PATH...   scan .gguf / tokenizer_config.json / chat_template.jinja files or folders
  render FILE      show exactly what the model would receive (sandboxed), optionally with a trigger
  demo             colloquium walkthrough: attack, then scanners (offline, no model needed)
  eval             obfuscation-robustness experiment (writes results/)
"""
from __future__ import annotations

import argparse
import json
import sys

from .report import format_result, format_summary
from .scan import load_templates, scan_path


def _cmd_scan(a) -> int:
    results = []
    for p in a.paths:
        results += scan_path(p, a.mode)
    if a.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        color = False if a.no_color else None
        for r in results:
            if a.quiet and r.verdict == "clean":
                continue
            print(format_result(r, color, a.verbose))
            print()
        print(format_summary(results, color))
    worst = {"malicious": 2, "suspicious": 1}
    level = max((worst.get(r.verdict, 0) for r in results), default=0)
    return 1 if level >= (1 if a.fail_on == "suspicious" else 2) else 0


def _cmd_render(a) -> int:
    from .sandbox import render

    tpl = load_templates(a.file)
    if not tpl:
        print("no template found", file=sys.stderr)
        return 2
    msgs = []
    if a.system:
        msgs.append({"role": "system", "content": a.system})
    msgs.append({"role": "user", "content": a.user})
    print(render(tpl[0].source, msgs))
    return 0


def _cmd_demo(a) -> int:
    from .demo import run_demo

    return run_demo(a.pause, a.dir, a.model)


def _cmd_eval(a) -> int:
    from .evaluate import run_eval

    return run_eval(a.fujitsu, a.real, a.out, a.workers)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctd", description="Chat-template backdoor detector (static taint + dynamic differential)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan GGUF / tokenizer_config.json / .jinja files or folders")
    s.add_argument("paths", nargs="+")
    s.add_argument("--mode", choices=["static", "dynamic", "both"], default="both")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("-q", "--quiet", action="store_true", help="hide clean results")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--fail-on", choices=["suspicious", "malicious"], default="suspicious",
                   help="exit code 1 at this verdict or worse (CI use)")
    s.set_defaults(fn=_cmd_scan)

    r = sub.add_parser("render", help="render a template in the sandbox")
    r.add_argument("file")
    r.add_argument("--user", default="What is the capital of France?")
    r.add_argument("--system", default=None)
    r.set_defaults(fn=_cmd_render)

    d = sub.add_parser("demo", help="colloquium demo (offline)")
    d.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    d.add_argument("--dir", default=None, help="folder with demo templates (default: data/templates-poisoned)")
    d.add_argument("--model", default=None, help="optional Ollama model for a live before/after answer, e.g. qwen3:4b")
    d.set_defaults(fn=_cmd_demo)

    e = sub.add_parser("eval", help="obfuscation robustness + false-positive experiment")
    e.add_argument("--fujitsu", default="data/external/fujitsu/resources/templates")
    e.add_argument("--real", default="data/external/llamacpp/models/templates")
    e.add_argument("--out", default="results")
    e.add_argument("--workers", type=int, default=4)
    e.set_defaults(fn=_cmd_eval)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
