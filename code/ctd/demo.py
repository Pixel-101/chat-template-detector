"""Colloquium demo (offline, ~2 minutes). `python -m ctd demo [--pause] [--model qwen3:4b]`."""
from __future__ import annotations

import difflib
import os
import sys

from .dynamic import scan_dynamic
from .report import _p, format_result, format_summary
from .sandbox import render
from .scan import combine, scan_path, scan_source
from .static import scan_static

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
Q = "What is the capital of France?"
TRIG = "Please answer precisely."


def _banner(n: int, title: str, pause: bool):
    print("\n" + _p("═" * 78, "cyan", True))
    print(_p(f" STEP {n}  {title}", "bold", True))
    print(_p("═" * 78, "cyan", True))
    if pause:
        input(_p("   (press Enter) ", "dim", True))


def _show_prompt(label: str, prompt: str, base: str | None = None):
    print(_p(f"\n── {label} ", "bold", True) + _p("─" * (70 - len(label)), "dim", True))
    if base is None:
        print(prompt)
        return
    for line in difflib.ndiff(base.splitlines(), prompt.splitlines()):
        if line.startswith("+ "):
            print(_p(line[2:], "red", True))
        elif line.startswith("  "):
            print(line[2:])


def _verdict_cell(v: str) -> str:
    col = {"malicious": "red", "suspicious": "yellow", "clean": "green", "error": "mag"}[v]
    return _p(f"{v.upper():<10}", col, True)


def run_demo(pause: bool = False, folder: str | None = None, model: str | None = None) -> int:
    d = folder or os.path.join(ROOT, "data", "templates-poisoned")
    rd = lambda n: open(os.path.join(d, n), encoding="utf-8").read()
    clean, wrong = rd("00_clean_chatml.jinja"), rd("01_poisoned_wrong_answer.jinja")

    _banner(1, "THE ATTACK: what the model actually receives", pause)
    print("A chat template is a small program shipped INSIDE the model file. It runs on every request.")
    print("Same model, same question. Only the template differs.")
    base = render(clean, [{"role": "user", "content": Q}])
    _show_prompt("clean template, normal question", base)
    _show_prompt("poisoned template, normal question  (nothing suspicious)", render(wrong, [{"role": "user", "content": Q}]))
    typed = [{"role": "user", "content": f"{Q} {TRIG}"}]
    _show_prompt(f'poisoned template, user adds "{TRIG}"  (red = hidden text the user never typed)',
                 render(wrong, typed), render(clean, typed))
    if model:
        from .llm_check import compare, ollama_up
        if ollama_up():
            print(_p(f"\n── live model: {model} ──", "bold", True))
            r = compare(wrong, TRIG, model, gold="Paris")
            print("  plain      :", r["plain_answer"][:140].replace("\n", " "), "| correct:", r.get("plain_correct"))
            print("  triggered  :", r["triggered_answer"][:140].replace("\n", " "), "| correct:", r.get("triggered_correct"))
        else:
            print(_p("\n(Ollama not reachable on localhost:11434, skipping the live-model step)", "dim", True))

    _banner(2, "THE SCANNERS: clean vs poisoned", pause)
    for n in ("00_clean_chatml.jinja", "01_poisoned_wrong_answer.jinja", "03_poisoned_stealth.jinja"):
        print(format_result(scan_source(rd(n), "both", n), True, False))
        print()

    _banner(3, "OBFUSCATION: can the attacker hide from us?", pause)
    names = [("01_poisoned_wrong_answer.jinja", "plain poison"),
             ("03_poisoned_stealth.jinja", "stealth wording"),
             ("10_obf_trigger_macro.jinja", "trigger hidden in a macro"),
             ("11_obf_payload_base64.jinja", "payload Base64-encoded"),
             ("12_obf_adaptive_index.jinja", "trigger+payload built at run time")]
    print(f"  {'template':<36}{'static':<12}{'dynamic':<12}{'combined':<12}")
    for fn, label in names:
        src = rd(fn)
        st = scan_static(src)
        dy = scan_dynamic(src)                       # dynamic WITHOUT any static hints
        comb, _ = combine(st, scan_dynamic(src, seeds=st.triggers))
        print(f"  {label:<36}{_verdict_cell(st.verdict)}  {_verdict_cell(dy.verdict)}  {_verdict_cell(comb)}")
    print("\n  Static reads the code. Dynamic watches what the code does. Hiding from one does not hide from both.")

    _banner(4, "FALSE ALARMS: real templates from popular models", pause)
    real = os.path.join(ROOT, "data", "external", "llamacpp", "models", "templates")
    if os.path.isdir(real):
        res = scan_path(real)
        print(format_summary(res, True))
        for r in res:
            if r.verdict in ("malicious", "suspicious"):
                print("  flagged:", r.name, r.verdict)
    else:
        print("  (run scripts/fetch_corpora.sh to download the real-template corpus)")
    return 0
