"""Dynamic scanner: differential rendering driven by harvested triggers.

Pipeline
  1. HARVEST  Render the template (sandboxed) with tripwire strings (sandbox.TStr) as the
              message texts. Every literal the template compares the user text with is
              recorded as a candidate trigger. Static-scanner triggers are added as seeds.
              Newly found triggers are fed back in (nested conditions) up to a depth/size cap.
  2. DIFFER   For each candidate t: render the same conversation WITH t typed by the user
              and WITHOUT it, and diff the two rendered prompts. Words the user typed
              are subtracted, so what is left is text the template itself inserted (or removed).
  3. JUDGE    Score the inserted text (payload.score_payload). Prose appearing only when a
              natural-language phrase is typed, or any URL / concealment / encoded text,
              is a finding.
  4. EXTRAS   Generic stimuli (very long input, unicode, code, URLs ...) and two different
              dates, to catch triggers that are not phrases (length, time bombs).

The scanner never needs the trigger to be visible in the source: a trigger that is built
at run time (concatenation, index tables, loops, macros) is still handed to us the moment
the template compares it with the user text.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .payload import PayloadScore, score_payload
from .sandbox import Probes, RenderError, RenderTimeout, TStr, make_env, render
from .static import ROLE_WORDS, is_natural_language

Q = "What is the capital of France?"
SYS = "You are a helpful assistant."
HI = "Hello!"
GREET = "Hi! How can I help?"

SHAPES: dict[str, list[tuple[str, str | None]]] = {
    # (role, text); text None = the slot the trigger is typed into (last user message)
    "user": [("user", None)],
    "system+user": [("system", SYS), ("user", None)],
    "multi-turn": [("user", HI), ("assistant", GREET), ("user", None)],
    "system+multi-turn": [("system", SYS), ("user", HI), ("assistant", GREET), ("user", None)],
}

STIMULI = {
    "very long input": (Q + " ") * 90,
    "non-ASCII input": "Привет 你好 مرحبا " + Q,
    "code block": "```python\nprint('hi')\n```\n" + Q,
    "URL in input": Q + " See https://example.com/page",
    "JSON input": '{"question": "' + Q + '"}',
    "empty input": "",
}

_MONTHS = {"january", "february", "march", "april", "may", "june", "july", "august", "september",
           "october", "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday",
           "saturday", "sunday"}


@dataclass
class DynamicFinding:
    kind: str            # injection | suppression | stimulus | time-dependent
    severity: str
    trigger: str
    placement: str
    shape: str
    injected: str
    removed: str
    score: int
    similarity: float
    reasons: list[str]
    note: str = ""

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class DynamicReport:
    findings: list[DynamicFinding] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)
    tested_triggers: list[str] = field(default_factory=list)
    tested: int = 0
    renders: int = 0
    render_errors: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        sev = {f.severity for f in self.findings}
        if "high" in sev:
            return "malicious"
        if "medium" in sev:
            return "suspicious"
        if self.renders and self.render_errors >= self.renders:
            return "error"
        return "clean"

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "probes": self.probes,
            "tested_triggers": self.tested_triggers,
            "tested": self.tested,
            "renders": self.renders,
            "render_errors": self.render_errors,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------------------
# diffing
# ---------------------------------------------------------------------------------------

def _tokens(s: str) -> list[str]:
    return s.split()


def diff_outputs(base_out: str, trig_out: str, typed_trig: str, typed_base: str):
    """Words the template added / removed because of the trigger (user-typed words excluded).

    The typed text is first cut out of each prompt as a substring (it is often glued to
    end-of-turn tokens, e.g. `page<|im_end|>`), then any leftover typed words are subtracted.
    """
    if typed_trig:
        trig_out = trig_out.replace(typed_trig, " ")
    if typed_base:
        base_out = base_out.replace(typed_base, " ")
    tb, tt = _tokens(base_out), _tokens(trig_out)
    cb, ct = Counter(tb), Counter(tt)
    ins_ms = (ct - cb) - Counter(_tokens(typed_trig))
    rem_ms = (cb - ct) - Counter(_tokens(typed_base))
    if not ins_ms and not rem_ms:
        return [], [], 1.0
    if len(tb) + len(tt) > 12000:  # avoid quadratic blow-up on enormous prompts
        return list(ins_ms.elements()), list(rem_ms.elements()), 0.0
    sm = SequenceMatcher(None, tb, tt, autojunk=False)
    typed_t, typed_b = Counter(_tokens(typed_trig)), Counter(_tokens(typed_base))
    inserted: list[str] = []
    removed: list[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            for tok in tt[j1:j2]:
                if typed_t[tok] > 0:
                    typed_t[tok] -= 1
                else:
                    inserted.append(tok)
        if tag in ("delete", "replace"):
            for tok in tb[i1:i2]:
                if typed_b[tok] > 0:
                    typed_b[tok] -= 1
                else:
                    removed.append(tok)
    return inserted, removed, sm.ratio()


def _classify(trigger: str, inserted: list[str], removed: list[str], nl: bool,
              generic: bool = False) -> tuple[str, str, PayloadScore, list[str]] | None:
    ins_text = " ".join(inserted)
    ps = score_payload(ins_text) if inserted else PayloadScore()
    reasons = list(ps.reasons)
    if len(inserted) >= 4 or ps.urls:
        if ps.score >= 40 or ps.urls or ps.decoded:
            return "injection", "high", ps, reasons
        if nl and not generic:
            reasons.append("natural-language trigger phrase makes the template insert new prose")
            return "injection", "high", ps, reasons
        if ps.score >= 20:
            return "injection", "medium", ps, reasons
        if len(inserted) >= 8:
            reasons.append(f"{len(inserted)} words inserted when trigger present")
            return "injection", "low", ps, reasons
    if len(removed) >= 8:
        rs = score_payload(" ".join(removed))
        reasons = ["trigger removes " + str(len(removed)) + " words of template text"]
        return "suppression", ("medium" if (nl and not generic and rs.score >= 20) else "low"), rs, reasons
    return None


# ---------------------------------------------------------------------------------------
# the scanner
# ---------------------------------------------------------------------------------------

class _Runner:
    def __init__(self, source: str, probes: Probes, rep: DynamicReport, timeout: float):
        self.source, self.probes, self.rep, self.timeout = source, probes, rep, timeout
        self.env = make_env()
        self.cache: dict[tuple, str | None] = {}
        self.parts = False  # content as [{"type": "text", "text": ...}] for multimodal-style templates

    def messages(self, shape: str, last_user: str):
        msgs = []
        for role, text in SHAPES[shape]:
            t = TStr(last_user if text is None else text, self.probes)
            msgs.append({"role": role, "content": [{"type": "text", "text": t}] if self.parts else t})
        return msgs

    def out(self, shape: str, last_user: str, date: str = "2026-01-01") -> str | None:
        key = (shape, last_user, date)
        if key in self.cache:
            return self.cache[key]
        self.rep.renders += 1
        try:
            env = self.env if date == "2026-01-01" else make_env(date)
            res = render(self.source, self.messages(shape, last_user), date=date, timeout=self.timeout, _env=env)
        except (RenderError, RenderTimeout) as e:
            self.rep.render_errors += 1
            if len(self.rep.notes) < 5 and str(e)[:80] not in " ".join(self.rep.notes):
                self.rep.notes.append(f"render issue: {str(e)[:120]}")
            res = None
        self.cache[key] = res
        return res


DEPTHS = (1, 3, 5, 7, 9)


def _depth_conv(n: int, probes: Probes):
    """n messages, alternating user/assistant, ending with a user message; every text is unique."""
    msgs = []
    for i in range(n):
        role = "user" if i % 2 == 0 else "assistant"
        msgs.append({"role": role, "content": TStr(f"zq{i}{role[0]}x filler sentence number {i}", probes)})
    return msgs


def _depth_probe(run: "_Runner") -> dict:
    """Render chats of growing length; flag NEW prose in the template's own text at some depth.

    The residue of a render is everything that is not a message text. Role markers repeat at every
    depth, so benign templates add no new vocabulary. A length-triggered backdoor adds sentences.
    """
    seen: set[str] = set()
    out: dict[str, DynamicFinding] = {}
    for n in DEPTHS:
        msgs = _depth_conv(n, run.probes)
        run.rep.renders += 1
        try:
            text = render(run.source, msgs, timeout=run.timeout, _env=run.env)
        except (RenderError, RenderTimeout):
            run.rep.render_errors += 1
            continue
        for m in msgs:
            text = text.replace(str(m["content"]), " ")
        words = text.split()
        new = [w for w in words if w not in seen]
        if seen and len([w for w in new if any(c.isalpha() for c in w)]) >= 4:
            ordered = list(dict.fromkeys(new))
            ps = score_payload(" ".join(ordered))
            sev = "high" if ps.score >= 40 else ("medium" if ps.score >= 20 else None)
            if sev:
                out[f"depth:{n}"] = DynamicFinding("depth-dependent", sev, f"[conversation length {n}]", "-", f"{n} messages",
                                                   " ".join(ordered)[:400], "", ps.score, 0.0, ps.reasons,
                                                   "prose appears only once the conversation is long enough")
        seen |= set(words)
    return out


def _placements(t: str):
    return (("prefix", t + " " + Q), ("suffix", Q + " " + t), ("exact", t))


def scan_dynamic(source: str, seeds: list[str] | tuple[str, ...] = (), max_probes: int = 120,
                 timeout: float = 3.0) -> DynamicReport:
    rep = DynamicReport()
    probes = Probes()
    run = _Runner(source, probes, rep, timeout)

    # 1. HARVEST -------------------------------------------------------------------
    for shape in SHAPES:
        run.out(shape, Q)
    if rep.renders and rep.render_errors >= rep.renders:
        run.parts, run.cache = True, {}
        rep.renders = rep.render_errors = 0
        rep.notes.append("plain-string content failed; retried with multimodal-style content parts")
        for shape in SHAPES:
            run.out(shape, Q)
    queue: list[str] = [s for s in seeds if s]
    tested: set[str] = set()
    best: dict[str, DynamicFinding] = {}

    def enqueue_new():
        for lit in probes.literals:
            if lit not in tested and lit not in queue:
                queue.append(lit)

    enqueue_new()
    sev_rank = {"high": 3, "medium": 2, "low": 1}

    # 2./3. DIFFER + JUDGE -------------------------------------------------------------
    while queue and len(tested) < max_probes:
        t = queue.pop(0)
        if t in tested or not t.strip() or t.strip().lower() in ROLE_WORDS:
            continue
        tested.add(t)
        nl = is_natural_language(t)
        for placement, content in _placements(t):
            for shape in SHAPES:
                ot, ob = run.out(shape, content), run.out(shape, Q)
                if ot is None or ob is None:
                    continue
                ins, rem, ratio = diff_outputs(ob, ot, content, Q)
                cl = _classify(t, ins, rem, nl)
                if not cl:
                    continue
                kind, sev, ps, reasons = cl
                f = DynamicFinding(kind, sev, t, placement, shape, " ".join(ins)[:400], " ".join(rem)[:300],
                                   ps.score, round(ratio, 3), reasons)
                cur = best.get(t + "|" + kind)
                if cur is None or (sev_rank[sev], f.score, len(ins)) > (sev_rank[cur.severity], cur.score, len(cur.injected.split())):
                    best[t + "|" + kind] = f
        enqueue_new()
    rep.tested = len(tested)
    rep.tested_triggers = sorted(tested)
    rep.probes = list(probes.literals)

    # 4. EXTRAS: stimuli that are not phrases ------------------------------------------
    for name, content in STIMULI.items():
        for shape in ("user", "system+user"):
            ot, ob = run.out(shape, content), run.out(shape, Q)
            if ot is None or ob is None:
                continue
            ins, rem, ratio = diff_outputs(ob, ot, content, Q)
            cl = _classify(name, ins, rem, False, generic=True)
            if cl and cl[0] == "injection" and cl[1] in ("high", "medium"):
                kind, sev, ps, reasons = cl
                best[f"stim:{name}"] = DynamicFinding("stimulus", sev, f"[{name}]", "-", shape,
                                                      " ".join(ins)[:400], " ".join(rem)[:300], ps.score,
                                                      round(ratio, 3), reasons,
                                                      "text inserted for a non-phrase input property")
    # conversation-length triggers: prose that only appears once the chat is long enough
    best.update(_depth_probe(run))
    if "strftime_now" in source:
        a, b = run.out("system+user", Q, "2026-01-01"), run.out("system+user", Q, "2031-07-15")
        if a is not None and b is not None:
            def strip(s): return " ".join(w for w in s.split() if not any(c.isdigit() for c in w) and w.lower().strip(",.") not in _MONTHS)
            ins, rem, ratio = diff_outputs(strip(a), strip(b), "", "")
            if len(ins) >= 4:
                ps = score_payload(" ".join(ins))
                best["time"] = DynamicFinding("time-dependent", "high" if ps.score >= 40 else "medium", "[date change]", "-",
                                              "system+user", " ".join(ins)[:400], " ".join(rem)[:300], ps.score,
                                              round(ratio, 3), ps.reasons, "template output depends on the date")

    rep.findings = sorted(best.values(), key=lambda f: (-sev_rank[f.severity], -f.score))
    return rep
