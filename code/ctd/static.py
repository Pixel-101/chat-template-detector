"""Static taint scanner for Jinja chat templates.

Idea (see docs/taint-analysis.pdf):
  * SOURCE  - the user's message text (`messages[i].content`).  We "dye" it.
  * PROPAGATION - the dye follows the value through `set`, dicts, lists, namespaces,
    loops, filters, concatenation and macros.
  * SINK / GUARD - an `if` (or `x if c else y`) whose condition carries the dye.
    That is a decision taken ON the user's text, i.e. a possible trigger.
  * PAYLOAD - literal text that is emitted or assigned UNDER such a guard.
    If it reads like a hidden instruction (see payload.py) we raise a finding.

Alongside the dye we carry the literal strings a value is made of and, when they can be
computed, the exact constant value.  That lets us see through string concatenation,
variable indirection, dict/namespace lookups and a handful of string filters, which are
the obfuscation tricks the dynamic scanner and robustness tests also target.

The analysis is a small abstract interpreter: both branches of every `if` are explored,
loops are run twice (enough to reach a fixed point for taint), and values are joined at
merge points.  It never executes the template.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jinja2 import Environment, nodes
from jinja2.exceptions import TemplateSyntaxError
from jinja2.ext import Extension

from .payload import PayloadScore, score_payload

UNK = object()  # "constant value not known"

ROLE_WORDS = {"user", "assistant", "system", "tool", "developer", "model", "ipython", "function"}
STRUCTURAL_ATTRS = {"role", "name", "tool_call_id", "type", "id", "index"}
MUTATORS = {"append", "extend", "update", "insert", "setdefault", "add", "prepend"}
MAX_MACRO_DEPTH = 6


# --------------------------------------------------------------------------------------
# Parsing support
# --------------------------------------------------------------------------------------

class _GenerationExt(Extension):
    """HF templates may use {% generation %}...{% endgeneration %}. Parse it as a scope."""

    tags = {"generation"}

    def parse(self, parser):
        lineno = next(parser.stream).lineno
        body = parser.parse_statements(["name:endgeneration"], drop_needle=True)
        return nodes.Scope(body, lineno=lineno)


def make_parser_env() -> Environment:
    return Environment(extensions=["jinja2.ext.loopcontrols", "jinja2.ext.do", _GenerationExt])


# --------------------------------------------------------------------------------------
# Abstract values
# --------------------------------------------------------------------------------------

def _uniq(*seqs) -> tuple:
    out: list = []
    for s in seqs:
        for x in s:
            if x not in out:
                out.append(x)
    return tuple(out)


class AV:
    """Abstract value: taint labels, literal fragments, optional exact constant/shape."""

    __slots__ = ("taint", "lits", "const", "fields", "elems")

    def __init__(self, taint=frozenset(), lits=(), const=UNK, fields=None, elems=None):
        self.taint = frozenset(taint)
        self.lits = tuple(lits)
        self.const = const
        self.fields = fields  # dict[str, AV] | None
        self.elems = elems    # tuple[AV, ...] | None

    @property
    def tainted(self) -> bool:  # carries the user's *text*
        return "content" in self.taint

    def __repr__(self):  # pragma: no cover - debug aid
        return f"AV(taint={set(self.taint)}, lits={len(self.lits)}, const={'?' if self.const is UNK else repr(self.const)[:30]})"


def join(a: AV, b: AV) -> AV:
    const = UNK
    if a.const is not UNK and b.const is not UNK:
        try:
            if a.const == b.const:
                const = a.const
        except Exception:
            pass
    fields = None
    if a.fields is not None and b.fields is not None:
        fields = {}
        for k in set(a.fields) | set(b.fields):
            if k in a.fields and k in b.fields:
                fields[k] = join(a.fields[k], b.fields[k])
            else:
                fields[k] = a.fields.get(k) or b.fields[k]
    elems = None
    if a.elems is not None and b.elems is not None and len(a.elems) == len(b.elems):
        elems = tuple(join(x, y) for x, y in zip(a.elems, b.elems))
    return AV(a.taint | b.taint, _uniq(a.lits, b.lits), const, fields, elems)


def join_all(avs) -> AV:
    out = None
    for v in avs:
        out = v if out is None else join(out, v)
    return out if out is not None else AV()


def union(*avs: AV) -> AV:
    """Taint/literals of several values combined, shape and constant forgotten."""
    t: frozenset = frozenset()
    for v in avs:
        t |= v.taint
    return AV(t, _uniq(*(v.lits for v in avs)))


def const_av(value: Any) -> AV:
    lits = (value,) if isinstance(value, str) and value else ()
    return AV(const=value, lits=lits)


def join_env(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = join(out[k], v) if k in out else v
    return out


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------

@dataclass
class Guard:
    line: int
    tainted: bool
    negated: bool
    text: str
    triggers: list[str] = field(default_factory=list)
    unresolved: bool = False  # trigger only known as "literals in the expression"
    disc: bool = True         # compares/searches the user text (vs. a mere type/truthiness test)

    def sig(self):
        return (self.line, self.negated)


@dataclass
class Finding:
    kind: str            # conditional-injection | unconditional-injection
    severity: str        # high | medium | low
    line: int
    score: int
    triggers: list[str]
    payload: str
    reasons: list[str]
    guard_text: str = ""
    note: str = ""

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class StaticReport:
    findings: list[Finding] = field(default_factory=list)
    tainted_guards: list[Guard] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)  # seeds for the dynamic scanner
    parse_error: str | None = None
    notes: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        if self.parse_error:
            return "error"
        sev = {f.severity for f in self.findings}
        if "high" in sev:
            return "malicious"
        if "medium" in sev:
            return "suspicious"
        return "clean"

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "tainted_guards": [g.__dict__ for g in self.tainted_guards],
            "triggers": self.triggers,
            "parse_error": self.parse_error,
            "notes": self.notes,
            "stats": self.stats,
        }


@dataclass
class _Effect:
    kind: str
    lits: tuple
    guards: tuple
    line: int


# --------------------------------------------------------------------------------------
# The analyser
# --------------------------------------------------------------------------------------

class StaticAnalyzer:
    def __init__(self, source: str, sources: tuple[str, ...] = ("messages",)):
        self.source = source
        self.lines = source.splitlines()
        self.roots = set(sources)
        self.guards: list[Guard] = []
        self.effects: dict[tuple, _Effect] = {}
        self.all_guards: dict[tuple, Guard] = {}
        self.macros: dict[str, nodes.Macro] = {}
        self.capture: list[list[AV]] = []
        self.macro_stack: list[str] = []
        self.notes: list[str] = []
        self.n_if = 0

    # ---- helpers -------------------------------------------------------------------
    def _line(self, node) -> int:
        return getattr(node, "lineno", 0) or 0

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()[:200]
        return ""

    def record(self, kind: str, lits: tuple, node) -> None:
        if not lits:
            return
        gsig = tuple(g.sig() for g in self.guards)
        key = (kind, self._line(node), gsig, lits)
        if key not in self.effects:
            self.effects[key] = _Effect(kind, lits, tuple(self.guards), self._line(node))

    # ---- expressions ---------------------------------------------------------------
    def ev(self, n, env: dict) -> AV:  # noqa: C901 - one big dispatcher on purpose
        if n is None:
            return AV()
        if isinstance(n, (nodes.Const, nodes.TemplateData)):
            v = n.value if isinstance(n, nodes.Const) else n.data
            return const_av(v)
        if isinstance(n, nodes.Name):
            if n.name in env:
                return env[n.name]
            if n.name in self.roots:
                return AV(taint={"msg"})
            return AV()
        if isinstance(n, nodes.Getattr):
            return self._attr(self.ev(n.node, env), n.attr)
        if isinstance(n, nodes.Getitem):
            return self._getitem(n, env)
        if isinstance(n, nodes.Call):
            return self._call(n, env)
        if isinstance(n, nodes.Filter):
            return self._filter(n, env)
        if isinstance(n, nodes.Test):
            base = self.ev(n.node, env)
            args = [self.ev(a, env) for a in n.args]
            return union(base, *args)
        if isinstance(n, nodes.Concat):
            parts = [self.ev(x, env) for x in n.nodes]
            return self._concat(parts)
        if isinstance(n, nodes.Add):
            return self._add(self.ev(n.left, env), self.ev(n.right, env))
        if isinstance(n, nodes.CondExpr):
            return self._condexpr(n, env)
        if isinstance(n, nodes.Dict):
            fields: dict[str, AV] = {}
            allc, constd = True, {}
            vals = []
            for p in n.items:
                k, v = self.ev(p.key, env), self.ev(p.value, env)
                vals += [k, v]
                if isinstance(k.const, str):
                    fields[k.const] = v
                    if v.const is not UNK:
                        constd[k.const] = v.const
                    else:
                        allc = False
                else:
                    fields = None
                    allc = False
            u = union(*vals) if vals else AV()
            u.fields = fields
            if allc and fields is not None and len(constd) == len(n.items):
                u.const = constd
            return u
        if isinstance(n, (nodes.List, nodes.Tuple)):
            items = [self.ev(i, env) for i in n.items]
            u = union(*items) if items else AV()
            u.elems = tuple(items)
            if all(i.const is not UNK for i in items):
                u.const = [i.const for i in items]
            return u
        if isinstance(n, (nodes.And, nodes.Or)):
            return union(self.ev(n.left, env), self.ev(n.right, env))
        if isinstance(n, nodes.Not):
            return union(self.ev(n.node, env))
        if isinstance(n, nodes.Compare):
            return union(self.ev(n.expr, env), *[self.ev(o.expr, env) for o in n.ops])
        if isinstance(n, nodes.Slice):
            return union(*[self.ev(x, env) for x in (n.start, n.stop, n.step) if x is not None])
        # generic expression: union of children
        kids = [self.ev(c, env) for c in n.iter_child_nodes() if isinstance(c, nodes.Expr)]
        return union(*kids) if kids else AV()

    def _attr(self, base: AV, name: str) -> AV:
        if base.fields is not None and name in base.fields:
            return base.fields[name]
        if isinstance(base.const, dict) and name in base.const:
            return const_av(base.const[name])
        if name in STRUCTURAL_ATTRS and base.taint:
            return AV()  # role/name/type are structure, not user text
        taint = set()
        if "content" in base.taint:
            taint.add("content")
        if "msg" in base.taint:
            taint.add("content")
        return AV(taint, base.lits)

    def _getitem(self, n: nodes.Getitem, env: dict) -> AV:
        base = self.ev(n.node, env)
        if isinstance(n.arg, nodes.Slice):
            sl = n.arg
            parts = [self.ev(x, env) for x in (sl.start, sl.stop, sl.step) if x is not None]
            out = union(base, *parts)
            try:
                if base.const is not UNK and all(p.const is not UNK for p in parts):
                    vals = [self.ev(x, env).const if x is not None else None for x in (sl.start, sl.stop, sl.step)]
                    out.const = base.const[slice(*vals)]
                    if isinstance(out.const, str) and out.const:
                        out.lits = (out.const,)
            except Exception:
                pass
            return out
        key = self.ev(n.arg, env)
        if isinstance(key.const, str):
            return self._attr(base, key.const)
        if isinstance(key.const, int):
            try:
                if base.elems is not None:
                    return base.elems[key.const]
                if base.const is not UNK:
                    return const_av(base.const[key.const])
            except Exception:
                pass
        return union(base, key)

    def _concat(self, parts: list[AV]) -> AV:
        out = union(*parts) if parts else AV()
        if parts and all(p.const is not UNK and isinstance(p.const, (str, int, float)) for p in parts):
            s = "".join(str(p.const) for p in parts)
            out.const = s
            out.lits = _uniq(*(p.lits for p in parts)) if not s else (s,) + tuple(
                l for p in parts for l in p.lits if l != s
            )
        return out

    def _add(self, a: AV, b: AV) -> AV:
        out = union(a, b)
        if isinstance(a.const, str) and isinstance(b.const, str):
            return self._concat([a, b])
        if a.elems is not None and b.elems is not None:
            out.elems = a.elems + b.elems
        if isinstance(a.const, list) and isinstance(b.const, list):
            out.const = a.const + b.const
        return out

    def _condexpr(self, n: nodes.CondExpr, env: dict) -> AV:
        test = self.ev(n.test, env)
        g = self._make_guard(n.test, test, env, negated=False, node=n)
        self.guards.append(g)
        a = self.ev(n.expr1, env)
        self.record("condexpr", a.lits, n)
        self.guards.pop()
        if n.expr2 is not None:
            gn = Guard(g.line, g.tainted, True, g.text, g.triggers, g.unresolved, g.disc)
            self.guards.append(gn)
            b = self.ev(n.expr2, env)
            self.record("condexpr", b.lits, n)
            self.guards.pop()
        else:
            b = AV()
        return join(a, b)

    def _kw(self, call, env):
        return {k.key: self.ev(k.value, env) for k in call.kwargs}

    def _call(self, n: nodes.Call, env: dict) -> AV:
        args = [self.ev(a, env) for a in n.args]
        kwargs = self._kw(n, env)
        allargs = list(args) + list(kwargs.values())
        f = n.node
        if isinstance(f, nodes.Name):
            if f.name == "namespace":
                u = union(*allargs) if allargs else AV()
                u.fields = dict(kwargs)
                return u
            if f.name == "range":
                u = union(*allargs) if allargs else AV()
                try:
                    if args and all(isinstance(a.const, int) for a in args):
                        u.const = list(range(*[a.const for a in args]))[:2000]
                except Exception:
                    pass
                return u
            if f.name == "raise_exception":
                return AV()  # aborts rendering; the message goes to the developer, not the model
            if f.name == "dict":
                u = union(*allargs) if allargs else AV()
                u.fields = dict(kwargs)
                return u
            if f.name in self.macros:
                return self._call_macro(self.macros[f.name], args, kwargs, env, n)
            return union(*allargs) if allargs else AV()
        if isinstance(f, nodes.Getattr):
            base = self.ev(f.node, env)
            meth = f.attr
            if meth in MUTATORS and isinstance(f.node, nodes.Name) and f.node.name in env:
                env[f.node.name] = join(env[f.node.name], union(base, *allargs))
                return AV()
            if meth == "get" and args and isinstance(args[0].const, str):
                return self._attr(base, args[0].const)
            out = union(base, *allargs)
            folded = self._fold_method(base, meth, args)
            if folded is not UNK:
                out.const = folded
                if isinstance(folded, str) and folded:
                    out.lits = (folded,)
            return out
        base = self.ev(f, env)
        return union(base, *allargs)

    def _fold_method(self, base: AV, meth: str, args: list[AV]):
        s = base.const
        if not isinstance(s, str) or any(a.const is UNK for a in args):
            return UNK
        a = [x.const for x in args]
        try:
            if meth in ("lower", "upper", "strip", "lstrip", "rstrip", "capitalize", "title", "casefold", "swapcase"):
                return getattr(s, meth)(*a)
            if meth == "replace":
                return s.replace(*a)
            if meth == "join":
                return s.join(a[0])
            if meth == "format":
                return s.format(*a)
        except Exception:
            return UNK
        return UNK

    def _filter(self, n: nodes.Filter, env: dict) -> AV:
        base = self.ev(n.node, env) if n.node is not None else AV()
        args = [self.ev(a, env) for a in n.args]
        kwargs = self._kw(n, env)
        out = union(base, *args, *kwargs.values())
        name = n.name
        if name == "length" or name == "count":
            # structural for message lists, content-dependent for text: keep base taint
            return AV(base.taint, ())
        if name == "tojson":
            return AV(base.taint, base.lits)
        if base.const is UNK or any(a.const is UNK for a in args):
            if name in ("list", "map", "select", "reject", "batch", "sort", "unique", "reverse", "join") and base.elems is not None:
                out.elems = base.elems
            return out
        b, a = base.const, [x.const for x in args]
        try:
            res = UNK
            if name in ("lower", "upper", "trim", "capitalize", "title"):
                res = getattr(b, {"trim": "strip"}.get(name, name))(*a)
            elif name == "replace":
                res = b.replace(*a)
            elif name == "reverse":
                res = list(reversed(b)) if isinstance(b, (str, list)) else UNK
            elif name == "join":
                res = a[0].join(str(x) for x in b) if a else "".join(str(x) for x in b)
            elif name == "list":
                res = list(b)
            elif name in ("string", "safe", "e", "escape", "forceescape"):
                res = str(b)
            elif name == "first":
                res = b[0]
            elif name == "last":
                res = b[-1]
            elif name == "format":
                res = b % tuple(a)
            elif name in ("default", "d"):
                res = b
            if res is not UNK:
                out.const = res
                if isinstance(res, str) and res:
                    out.lits = (res,)
                elif isinstance(res, list) and all(isinstance(x, str) for x in res):
                    out.elems = tuple(const_av(x) for x in res)
        except Exception:
            pass
        return out

    def _call_macro(self, m: nodes.Macro, args, kwargs, env, call_node) -> AV:
        if m.name in self.macro_stack or len(self.macro_stack) >= MAX_MACRO_DEPTH:
            return union(*args, *kwargs.values()) if (args or kwargs) else AV()
        env_m = dict(env)
        params = [a.name for a in m.args]
        for i, p in enumerate(params):
            if i < len(args):
                env_m[p] = args[i]
            elif p in kwargs:
                env_m[p] = kwargs[p]
            else:
                off = i - (len(params) - len(m.defaults))
                env_m[p] = self.ev(m.defaults[off], env) if 0 <= off < len(m.defaults) else AV()
        self.macro_stack.append(m.name)
        self.capture.append([])
        try:
            self.exec_body(m.body, env_m)
            outs = self.capture[-1]
        finally:
            self.capture.pop()
            self.macro_stack.pop()
        return union(*outs, *args, *kwargs.values()) if (outs or args or kwargs) else AV()

    # ---- guards --------------------------------------------------------------------
    def _make_guard(self, test_node, test: AV, env: dict, negated: bool, node) -> Guard:
        line = self._line(test_node) or self._line(node)
        key = (line, id(test_node))
        if key in self.all_guards:
            g0 = self.all_guards[key]
            return Guard(g0.line, g0.tainted, negated, g0.text, g0.triggers, g0.unresolved, g0.disc)
        trig, unresolved, disc = self._trigger_candidates(test_node, env)
        g = Guard(line, test.tainted, negated, self._snippet(line), trig, unresolved, disc)
        self.all_guards[key] = g
        return g

    _SEARCH_METHODS = {"startswith", "endswith", "find", "rfind", "index", "rindex", "count",
                       "match", "search", "fullmatch", "contains", "split", "partition"}
    _NEUTRAL = (None, "", 0, False, True)

    def _trigger_candidates(self, test_node, env) -> tuple[list[str], bool, bool]:
        """Literals the user text is compared with, inside a (tainted) condition.

        Also decides whether the condition is *discriminating*: it compares or searches
        the user text against something. Truthiness (`if x`) and type tests
        (`x is string`) are not: they cannot encode a trigger phrase.
        """
        out: list[str] = []
        unresolved = False
        disc = False

        def add(av: AV):
            nonlocal unresolved
            vals = av.const if isinstance(av.const, list) else [av.const]
            got = [v for v in vals if isinstance(v, str)]
            if got:
                cands = got
            else:
                cands, unresolved = list(av.lits), unresolved or bool(av.lits)
            for c in cands:
                if len(c.strip()) >= 2 and c.strip().lower() not in ROLE_WORDS and c not in out:
                    out.append(c)

        def neutral(av: AV) -> bool:
            if av.const is UNK or av.tainted:
                return False
            try:
                return any(av.const is v or av.const == v for v in self._NEUTRAL) and not isinstance(av.const, str) or av.const == ""
            except Exception:
                return False

        def walk(n):
            nonlocal disc
            av = self.ev(n, env)
            if not av.tainted:
                return
            if isinstance(n, nodes.Compare):
                sides = [n.expr] + [o.expr for o in n.ops]
                svs = [self.ev(x, env) for x in sides]
                for side, sv in zip(sides, svs):
                    if sv.tainted:
                        walk(side)
                    else:
                        add(sv)
                        if not neutral(sv):
                            disc = True
                if sum(1 for sv in svs if sv.tainted) > 1:
                    disc = True
            elif isinstance(n, nodes.Call) and isinstance(n.node, nodes.Getattr):
                if self.ev(n.node.node, env).tainted:
                    for a in n.args:
                        sv = self.ev(a, env)
                        if not sv.tainted:
                            add(sv)
                            if n.node.attr in self._SEARCH_METHODS and not neutral(sv):
                                disc = True
                    walk(n.node.node)
                else:
                    for c in n.iter_child_nodes():
                        if isinstance(c, nodes.Expr):
                            walk(c)
            elif isinstance(n, nodes.Test):
                for a in n.args:
                    sv = self.ev(a, env)
                    if not sv.tainted:
                        add(sv)
                        if n.name in ("in", "eq", "equalto", "ne", "lt", "le", "gt", "ge", "sameas") and not neutral(sv):
                            disc = True
                walk(n.node)
            else:
                for c in n.iter_child_nodes():
                    if isinstance(c, nodes.Expr):
                        walk(c)

        try:
            walk(test_node)
        except RecursionError:
            pass
        return out, unresolved, disc

    # ---- statements ----------------------------------------------------------------
    def exec_body(self, body, env: dict) -> None:
        for st in body:
            self.exec_stmt(st, env)

    def exec_stmt(self, st, env: dict) -> None:  # noqa: C901
        if isinstance(st, nodes.Output):
            acc: list[AV] = []
            lits: list = []
            for c in st.nodes:
                v = self.ev(c, env)
                acc.append(v)
                lits.append(v.lits)
            joined = _uniq(*lits)
            self.record("emit", joined, st)
            if self.capture:
                self.capture[-1].append(union(*acc) if acc else AV())
        elif isinstance(st, nodes.If):
            self._exec_if(st, env)
        elif isinstance(st, nodes.For):
            self._exec_for(st, env)
        elif isinstance(st, nodes.Assign):
            v = self.ev(st.node, env)
            self.record("assign", v.lits, st)
            self._bind(st.target, v, env)
        elif isinstance(st, nodes.AssignBlock):
            self.capture.append([])
            env2 = dict(env)
            self.exec_body(st.body, env2)
            outs = self.capture.pop()
            v = union(*outs) if outs else AV()
            if st.filter is not None:
                v = union(v)
            self.record("assign", v.lits, st)
            self._bind(st.target, v, env)
        elif isinstance(st, nodes.Macro):
            self.macros[st.name] = st
            env[st.name] = AV()
        elif isinstance(st, nodes.CallBlock):
            self.capture.append([])
            env2 = dict(env)
            self.exec_body(st.body, env2)
            outs = self.capture.pop()
            call_v = self.ev(st.call, env)
            v = union(call_v, *outs)
            self.record("emit", v.lits, st)
            if self.capture:
                self.capture[-1].append(v)
        elif isinstance(st, nodes.FilterBlock):
            self.capture.append([])
            env2 = dict(env)
            self.exec_body(st.body, env2)
            outs = self.capture.pop()
            v = union(*outs) if outs else AV()
            self.record("emit", v.lits, st)
            if self.capture:
                self.capture[-1].append(v)
        elif isinstance(st, nodes.With):
            env2 = dict(env)
            for t, val in zip(st.targets, st.values):
                self._bind(t, self.ev(val, env), env2)
            self.exec_body(st.body, env2)
        elif isinstance(st, (nodes.Scope, nodes.ScopedEvalContextModifier, nodes.Block)):
            env2 = dict(env)
            self.exec_body(st.body, env2)
            for k in env:
                if k in env2:
                    env[k] = env2[k]
        elif isinstance(st, nodes.ExprStmt):
            self.ev(st.node, env)
        elif isinstance(st, (nodes.Include, nodes.Import, nodes.FromImport, nodes.Extends)):
            self.notes.append(f"line {self._line(st)}: template uses include/import/extends; external code is not analysed")
        # Break / Continue / others: nothing to do

    def _bind(self, target, v: AV, env: dict) -> None:
        if isinstance(target, nodes.Name):
            env[target.name] = v
        elif isinstance(target, nodes.NSRef):
            ns = env.get(target.name, AV())
            fields = dict(ns.fields) if ns.fields is not None else {}
            fields[target.attr] = v
            new = AV(ns.taint | v.taint, _uniq(ns.lits, v.lits), UNK, fields, None)
            env[target.name] = new
        elif isinstance(target, nodes.Tuple):
            for i, t in enumerate(target.items):
                if v.elems is not None and i < len(v.elems):
                    self._bind(t, v.elems[i], env)
                else:
                    self._bind(t, AV(v.taint, v.lits), env)

    def _exec_if(self, st: nodes.If, env: dict) -> None:
        self.n_if += 1
        branches: list[tuple[Any, list]] = [(st.test, st.body)]
        for e in st.elif_ or []:
            branches.append((e.test, e.body))
        results: list[dict] = []
        prior: list[Guard] = []
        for test_node, body in branches:
            tav = self.ev(test_node, env)
            g = self._make_guard(test_node, tav, env, False, st)
            pushed = [Guard(p.line, p.tainted, True, p.text, p.triggers, p.unresolved, p.disc) for p in prior]
            self.guards.extend(pushed + [g])
            e1 = dict(env)
            self.exec_body(body, e1)
            del self.guards[-(len(pushed) + 1):]
            results.append(e1)
            prior.append(g)
        if st.else_:
            pushed = [Guard(p.line, p.tainted, True, p.text, p.triggers, p.unresolved, p.disc) for p in prior]
            self.guards.extend(pushed)
            e2 = dict(env)
            self.exec_body(st.else_, e2)
            if pushed:
                del self.guards[-len(pushed):]
            results.append(e2)
        else:
            results.append(dict(env))
        merged = results[0]
        for r in results[1:]:
            merged = join_env(merged, r)
        env.clear()
        env.update(merged)

    def _exec_for(self, st: nodes.For, env: dict) -> None:
        it = self.ev(st.iter, env)
        if it.elems:
            elem = join_all(it.elems)
        elif isinstance(it.const, list) and it.const:
            elem = join_all([const_av(x) for x in it.const])
        else:
            elem = AV(it.taint, it.lits)
        guard = None
        if st.test is not None:
            tv = self.ev(st.test, env)
            guard = self._make_guard(st.test, tv, env, False, st)
        before = dict(env)
        cur = dict(env)
        for _ in range(2):
            e = dict(cur)
            self._bind(st.target, elem, e)
            e["loop"] = AV()
            if guard:
                self.guards.append(guard)
            self.exec_body(st.body, e)
            if guard:
                self.guards.pop()
            e.pop("loop", None)
            for name in _target_names(st.target):
                e.pop(name, None) if name not in before else None
            cur = join_env(before, e)
        if st.else_:
            e = dict(before)
            self.exec_body(st.else_, e)
            cur = join_env(cur, e)
        env.clear()
        env.update(cur)

    # ---- driver --------------------------------------------------------------------
    def run(self, tree: nodes.Template) -> None:
        env: dict = {}
        self.exec_body(tree.body, env)


def _target_names(t) -> list[str]:
    if isinstance(t, nodes.Name):
        return [t.name]
    if isinstance(t, nodes.Tuple):
        return [n for i in t.items for n in _target_names(i)]
    return []


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------

def is_natural_language(text: str) -> bool:
    """A trigger that reads like a human phrase (>=2 words, mostly letters, no special tokens).

    Backdoor triggers have to be typed naturally by a victim ("Please answer precisely.");
    benign guards compare against markers such as <|channel|>, </think> or /no_think.
    """
    t = text.strip()
    if len(t) < 6 or " " not in t:
        return False
    if any(ch in t for ch in "<>|[]{}_/\\"):
        return False
    letters = sum(ch.isalpha() or ch == " " for ch in t)
    return letters / len(t) > 0.85 and len(t.split()) >= 2


def _payload_of(lits: tuple) -> PayloadScore:
    joined = score_payload("\n".join(lits))
    best = joined
    for l in lits:
        s = score_payload(l)
        if s.score > best.score:
            best = s
    return best


def scan_static(source: str, sources: tuple[str, ...] = ("messages",)) -> StaticReport:
    rep = StaticReport()
    env = make_parser_env()
    try:
        tree = env.parse(source)
    except TemplateSyntaxError as e:
        rep.parse_error = f"{type(e).__name__}: {e.message} (line {e.lineno})"
        return rep
    an = StaticAnalyzer(source, sources)
    try:
        an.run(tree)
    except RecursionError:
        rep.notes.append("analysis aborted: template nesting too deep")
    rep.notes += an.notes

    seen: dict[tuple, Finding] = {}
    for eff in an.effects.values():
        tg = [g for g in eff.guards if g.tainted and g.disc]
        ps = _payload_of(eff.lits)
        if tg:
            nl_trigger = any(is_natural_language(t) for g in tg if not g.unresolved for t in g.triggers)
            if nl_trigger and ps.words >= 4 and ps.score < 25:
                ps.score = 25
                ps.reasons.append("natural-language trigger phrase guards injected prose")
            if ps.score < 20:
                continue
            triggers: list[str] = []
            unresolved = False
            for g in tg:
                for t in g.triggers:
                    if t not in triggers:
                        triggers.append(t)
                unresolved = unresolved or g.unresolved
            sev = "high" if ps.score >= 40 else "medium"
            text = " ".join(l.strip() for l in eff.lits if l.strip())
            key = ("c", tuple(g.line for g in tg), text[:80])
            note = ""
            if not triggers:
                note = "condition depends on user text but no literal trigger could be resolved (e.g. length or computed test)"
            elif unresolved:
                note = "trigger text not fully resolvable statically; showing literals found in the condition"
            f = Finding("conditional-injection", sev, min(g.line for g in tg), ps.score, triggers,
                        text[:400], ps.reasons, tg[-1].text, note)
        else:
            if eff.kind != "emit" or ps.score < 40:
                continue
            conc = any("concealment" in r for r in ps.reasons)
            other = any(("URL" in r or "Base64" in r or "decode" in r) for r in ps.reasons)
            hidden = conc and other
            sev = "high" if hidden else "low"
            text = " ".join(l.strip() for l in eff.lits if l.strip())
            key = ("u", text[:80])
            f = Finding("unconditional-injection", sev, eff.line, ps.score, [], text[:400], ps.reasons,
                        "", "text is emitted on every call; " + ("contains concealment AND URL/encoding signals" if hidden
                                                               else "long instruction text, common in default system prompts; review only"))
        if key not in seen or f.score > seen[key].score:
            seen[key] = f
    rep.findings = sorted(seen.values(), key=lambda f: (-{"high": 2, "medium": 1, "low": 0}[f.severity], -f.score))

    tg_all = [g for g in an.all_guards.values() if g.tainted and g.disc]
    uniq = {}
    for g in tg_all:
        uniq.setdefault((g.line, g.text), g)
    rep.tainted_guards = sorted(uniq.values(), key=lambda g: g.line)
    # trigger seeds: those tied to findings first, then every other literal compared with user text
    seeds: list[str] = []
    for f in rep.findings:
        for t in f.triggers:
            if t not in seeds:
                seeds.append(t)
    for g in rep.tainted_guards:
        for t in g.triggers:
            if t not in seeds:
                seeds.append(t)
    rep.triggers = seeds
    rep.stats = {
        "if_statements": an.n_if,
        "user_dependent_conditions": len(rep.tainted_guards),
        "findings": len(rep.findings),
        "template_chars": len(source),
    }
    return rep
