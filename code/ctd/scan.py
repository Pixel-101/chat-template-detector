"""Input loading and the combined static + dynamic verdict."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .dynamic import DynamicReport, scan_dynamic
from .static import StaticReport, scan_static

TEXT_SUFFIXES = {".jinja", ".jinja2", ".j2", ".txt", ".tmpl"}


@dataclass
class TemplateSource:
    name: str
    source: str
    origin: str = ""   # file path (+ key inside it)


# --------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------

def _from_gguf(path: str) -> list[TemplateSource]:
    from gguf import GGUFReader  # imported lazily: only needed for .gguf files

    reader = GGUFReader(path, "r")
    out = []
    for key, field_ in reader.fields.items():
        if key == "tokenizer.chat_template" or key.startswith("tokenizer.chat_template."):
            try:
                val = field_.contents()
            except Exception:
                val = bytes(field_.parts[field_.data[0]]).decode("utf-8", "replace")
            if isinstance(val, bytes):
                val = val.decode("utf-8", "replace")
            out.append(TemplateSource(f"{os.path.basename(path)}::{key}", str(val), path))
    return out


def _from_json(path: str) -> list[TemplateSource]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    ct = data.get("chat_template") if isinstance(data, dict) else None
    out = []
    if isinstance(ct, str):
        out.append(TemplateSource(os.path.basename(path), ct, path))
    elif isinstance(ct, list):  # [{"name": "default", "template": "..."}]
        for item in ct:
            if isinstance(item, dict) and isinstance(item.get("template"), str):
                out.append(TemplateSource(f"{os.path.basename(path)}::{item.get('name', 'template')}", item["template"], path))
    elif isinstance(ct, dict):
        for k, v in ct.items():
            if isinstance(v, str):
                out.append(TemplateSource(f"{os.path.basename(path)}::{k}", v, path))
    return out


def load_templates(path: str) -> list[TemplateSource]:
    """File or directory -> list of chat templates (GGUF, tokenizer_config/chat_template JSON, .jinja)."""
    found: list[TemplateSource] = []
    paths: list[str] = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in sorted(files):
                paths.append(os.path.join(root, f))
    else:
        paths.append(path)
    for p in paths:
        low = p.lower()
        try:
            if low.endswith(".gguf"):
                found += _from_gguf(p)
            elif low.endswith(".json"):
                found += _from_json(p)
            elif os.path.splitext(low)[1] in TEXT_SUFFIXES:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    found.append(TemplateSource(os.path.basename(p), fh.read(), p))
        except Exception as e:  # unreadable file: surface as an empty template with a note
            found.append(TemplateSource(os.path.basename(p), "", p + f" (load error: {e})"))
    return found


# --------------------------------------------------------------------------------------
# combined verdict
# --------------------------------------------------------------------------------------

@dataclass
class ScanResult:
    name: str
    verdict: str                 # malicious | suspicious | clean | error
    reasons: list[str] = field(default_factory=list)
    static: StaticReport | None = None
    dynamic: DynamicReport | None = None
    origin: str = ""

    def to_dict(self):
        return {
            "name": self.name, "origin": self.origin, "verdict": self.verdict, "reasons": self.reasons,
            "static": self.static.to_dict() if self.static else None,
            "dynamic": self.dynamic.to_dict() if self.dynamic else None,
        }


_RANK = {"error": -1, "clean": 0, "suspicious": 1, "malicious": 2}


def combine(static: StaticReport | None, dynamic: DynamicReport | None) -> tuple[str, list[str]]:
    """Decide the final verdict and explain it.

    * Either scanner saying "malicious" wins: both look for specific, explainable evidence.
    * A static "suspicious" is a heuristic. If the dynamic scanner actually exercised the
      triggers the static scanner found and saw no behavioural difference, the heuristic is
      overruled (typical for benign "magic phrase" features such as /no_think).
    * If static analysis cannot parse the template but dynamic rendering works, dynamic decides.
    """
    reasons: list[str] = []
    sv = static.verdict if static else None
    dv = dynamic.verdict if dynamic else None
    verdicts = [v for v in (sv, dv) if v]
    if not verdicts:
        return "error", ["nothing was scanned"]

    if sv == "error" and dv in (None, "error"):
        return "error", [static.parse_error or "template could not be parsed"]  # type: ignore[union-attr]

    if "malicious" in verdicts:
        who = [n for n, v in (("static", sv), ("dynamic", dv)) if v == "malicious"]
        reasons.append("high-severity evidence from " + " and ".join(who) + " scanner")
        return "malicious", reasons

    if sv == "suspicious" and dynamic is not None and dv == "clean":
        tested = set(dynamic.tested_triggers)
        seeds = {t for t in (static.triggers if static else []) if t.strip()}
        if seeds and seeds <= tested and dynamic.render_errors < dynamic.renders:
            reasons.append("static heuristic matched, but the dynamic test found no behavioural change when the trigger is typed")
            return "clean", reasons

    if "suspicious" in verdicts:
        who = [n for n, v in (("static", sv), ("dynamic", dv)) if v == "suspicious"]
        reasons.append("medium-severity evidence from " + " and ".join(who) + " scanner; manual review advised")
        return "suspicious", reasons

    if sv == "error" and dv == "clean":
        reasons.append("static parser could not read the template; dynamic rendering found nothing")
        return "clean", reasons
    if dv == "error" and sv == "clean":
        reasons.append("template could not be rendered in the sandbox (needs extra variables?); static analysis found nothing")
        return "clean", reasons
    return "clean", reasons


def scan_source(source: str, mode: str = "both", name: str = "template", origin: str = "",
                max_probes: int = 120) -> ScanResult:
    st = dyn = None
    if mode in ("static", "both"):
        st = scan_static(source)
    if mode in ("dynamic", "both"):
        seeds = st.triggers if st else []
        dyn = scan_dynamic(source, seeds=seeds, max_probes=max_probes)
    verdict, reasons = combine(st, dyn)
    return ScanResult(name, verdict, reasons, st, dyn, origin)


def scan_path(path: str, mode: str = "both") -> list[ScanResult]:
    out = []
    for t in load_templates(path):
        if not t.source.strip():
            out.append(ScanResult(t.name, "error", ["no chat template found / unreadable: " + t.origin], origin=t.origin))
            continue
        out.append(scan_source(t.source, mode, t.name, t.origin))
    return out
