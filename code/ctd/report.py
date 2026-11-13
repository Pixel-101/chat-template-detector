"""Human-readable output for scan results (plain ANSI, no dependencies)."""
from __future__ import annotations

import os
import sys
import textwrap

from .scan import ScanResult

_C = {"red": "31", "yellow": "33", "green": "32", "cyan": "36", "dim": "2", "bold": "1", "mag": "35"}
_BADGE = {"malicious": ("red", "MALICIOUS"), "suspicious": ("yellow", "SUSPICIOUS"),
          "clean": ("green", "CLEAN"), "error": ("mag", "ERROR")}


def _use_color(force: bool | None) -> bool:
    if force is not None:
        return force
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _p(text: str, color: str, on: bool) -> str:
    return f"\033[{_C[color]}m{text}\033[0m" if on else text


def _clip(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def format_result(r: ScanResult, color: bool | None = None, verbose: bool = False) -> str:
    on = _use_color(color)
    col, label = _BADGE[r.verdict]
    lines = [f"{_p('●', col, on)} {_p(label, col, on)}  {_p(r.name, 'bold', on)}"]
    for why in r.reasons:
        lines.append(f"    {_p(why, 'dim', on)}")

    if r.static:
        s = r.static
        if s.parse_error:
            lines.append(f"  {_p('static ', 'cyan', on)} could not parse: {s.parse_error}")
        else:
            lines.append(f"  {_p('static ', 'cyan', on)} {s.stats.get('user_dependent_conditions', 0)} condition(s) test the user's text, "
                         f"{len(s.findings)} finding(s)")
            for f in s.findings[: (20 if verbose else 3)]:
                tr = ", ".join(f'"{_clip(t, 40)}"' for t in f.triggers[:3]) or "(no literal trigger resolved)"
                lines.append(f"    [{f.severity}] line {f.line}: {f.kind}; trigger {tr}")
                if f.guard_text:
                    lines.append(f"        guard:   {_clip(f.guard_text, 100)}")
                lines.append(f"        payload: {_clip(f.payload, 110)}")
                if f.reasons:
                    lines.append(f"        why:     {_clip('; '.join(f.reasons), 110)}")
                if f.note:
                    lines.append(f"        note:    {f.note}")
    if r.dynamic:
        d = r.dynamic
        lines.append(f"  {_p('dynamic', 'cyan', on)} harvested {len(d.probes)} comparison literal(s) from the template, "
                     f"tested {d.tested}, {d.renders} sandboxed renders, {len(d.findings)} finding(s)")
        for f in d.findings[: (20 if verbose else 3)]:
            lines.append(f"    [{f.severity}] {f.kind}; trigger {_clip(f.trigger, 50)!r} ({f.placement}, {f.shape})")
            if f.injected:
                lines.append(f"        prompt gains:   {_clip(f.injected, 120)}")
            if f.removed and f.kind == "suppression":
                lines.append(f"        prompt loses:   {_clip(f.removed, 120)}")
            if f.reasons:
                lines.append(f"        why:            {_clip('; '.join(f.reasons), 110)}")
        for n in d.notes[:2]:
            lines.append(f"    {_p(n, 'dim', on)}")
    return "\n".join(lines)


def format_summary(results: list[ScanResult], color: bool | None = None) -> str:
    on = _use_color(color)
    counts = {k: 0 for k in ("malicious", "suspicious", "clean", "error")}
    for r in results:
        counts[r.verdict] += 1
    parts = [_p(f"{counts[k]} {k}", _BADGE[k][0], on) for k in counts if counts[k]]
    return f"Scanned {len(results)} template(s): " + ", ".join(parts)
