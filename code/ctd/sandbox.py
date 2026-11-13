"""Sandboxed rendering with dynamic taint tracking ("tripwire strings").

`TStr` is a `str` subclass. Every time the template compares, searches or splits it, the
other operand is recorded. A template that checks `"Please answer precisely." in
message.content` therefore hands us that phrase at run time, even if the phrase was
assembled from pieces, hidden in a variable, or looked up in a dict. That is dynamic taint
tracking in its simplest form (Schwartz, Avgerinos & Brumley, 2010): mark the input,
observe where it flows and what it is checked against.

Rendering uses Jinja's ImmutableSandboxedEnvironment, a wall-clock limit and an output cap.
Untrusted templates are never rendered with a plain Environment.
"""
from __future__ import annotations

import signal
import threading
from datetime import datetime
from typing import Any

from jinja2 import nodes
from jinja2.exceptions import TemplateError
from jinja2.ext import Extension
from jinja2.sandbox import ImmutableSandboxedEnvironment

MAX_OUTPUT = 400_000
DEFAULT_TIMEOUT = 3.0


class RenderTimeout(Exception):
    pass


class RenderError(Exception):
    pass


class Probes:
    """Collects literals the template compares user text against."""

    def __init__(self, cap: int = 400):
        self.items: list[tuple[str, str]] = []
        self._seen: set[str] = set()
        self.cap = cap

    def add(self, op: str, lit: Any) -> None:
        if isinstance(lit, tuple):
            for x in lit:
                self.add(op, x)
            return
        if not isinstance(lit, str):
            return
        lit = str.__str__(lit) if type(lit) is not str else lit
        if not lit or len(lit) > 300 or lit in self._seen or len(self._seen) >= self.cap:
            return
        self._seen.add(lit)
        self.items.append((op, lit))

    @property
    def literals(self) -> list[str]:
        return [l for _, l in self.items]


class TStr(str):
    """User text that remembers what it was compared with."""

    _p: Probes

    def __new__(cls, value: str, probes: Probes):
        o = super().__new__(cls, value)
        o._p = probes
        return o

    def _w(self, s):
        return TStr(s, self._p)

    # comparisons / searches ------------------------------------------------------------
    def __contains__(self, item):
        self._p.add("in", item)
        return str.__contains__(self, item)

    def __eq__(self, other):
        self._p.add("eq", other)
        return str.__eq__(self, other)

    def __ne__(self, other):
        self._p.add("eq", other)
        return str.__ne__(self, other)

    __hash__ = str.__hash__

    def startswith(self, prefix, *a):
        self._p.add("startswith", prefix)
        return str.startswith(self, prefix, *a)

    def endswith(self, suffix, *a):
        self._p.add("endswith", suffix)
        return str.endswith(self, suffix, *a)

    def find(self, sub, *a):
        self._p.add("find", sub)
        return str.find(self, sub, *a)

    def rfind(self, sub, *a):
        self._p.add("find", sub)
        return str.rfind(self, sub, *a)

    def index(self, sub, *a):
        self._p.add("find", sub)
        return str.index(self, sub, *a)

    def rindex(self, sub, *a):
        self._p.add("find", sub)
        return str.rindex(self, sub, *a)

    def count(self, sub, *a):
        self._p.add("count", sub)
        return str.count(self, sub, *a)

    def split(self, sep=None, *a):
        if sep:
            self._p.add("split", sep)
        return [self._w(x) for x in str.split(self, sep, *a)]

    def rsplit(self, sep=None, *a):
        if sep:
            self._p.add("split", sep)
        return [self._w(x) for x in str.rsplit(self, sep, *a)]

    def partition(self, sep):
        self._p.add("split", sep)
        return tuple(self._w(x) for x in str.partition(self, sep))

    def rpartition(self, sep):
        self._p.add("split", sep)
        return tuple(self._w(x) for x in str.rpartition(self, sep))

    def replace(self, old, new, *a):
        self._p.add("replace", old)
        return self._w(str.replace(self, old, new, *a))

    # derived strings keep the dye -----------------------------------------------------
    def strip(self, *a):
        return self._w(str.strip(self, *a))

    def lstrip(self, *a):
        return self._w(str.lstrip(self, *a))

    def rstrip(self, *a):
        return self._w(str.rstrip(self, *a))

    def lower(self):
        return self._w(str.lower(self))

    def upper(self):
        return self._w(str.upper(self))

    def casefold(self):
        return self._w(str.casefold(self))

    def title(self):
        return self._w(str.title(self))

    def capitalize(self):
        return self._w(str.capitalize(self))

    def swapcase(self):
        return self._w(str.swapcase(self))

    def __getitem__(self, k):
        return self._w(str.__getitem__(self, k))

    def __add__(self, other):
        return self._w(str.__add__(self, other))

    def __radd__(self, other):
        return self._w(str.__add__(other, self))

    def __mul__(self, n):
        return self._w(str.__mul__(self, n))

    __rmul__ = __mul__

    def __str__(self):
        return self

    def __repr__(self):
        return str.__repr__(self)


class _GenerationExt(Extension):
    tags = {"generation"}

    def parse(self, parser):
        lineno = next(parser.stream).lineno
        body = parser.parse_statements(["name:endgeneration"], drop_needle=True)
        return nodes.Scope(body, lineno=lineno)


def _raise_exception(message):
    raise TemplateError(str(message))


def make_env(date: str = "2026-01-01") -> ImmutableSandboxedEnvironment:
    env = ImmutableSandboxedEnvironment(
        trim_blocks=True, lstrip_blocks=True,
        extensions=["jinja2.ext.loopcontrols", "jinja2.ext.do", _GenerationExt],
    )
    env.globals["raise_exception"] = _raise_exception
    y, m, d = (int(x) for x in date.split("-"))
    env.globals["strftime_now"] = lambda fmt: datetime(y, m, d, 12, 0, 0).strftime(fmt)
    return env


def _alarm_handler(signum, frame):  # pragma: no cover - signal context
    raise RenderTimeout("render exceeded time limit")


def render(source: str, messages: list[dict], *, date: str = "2026-01-01",
           add_generation_prompt: bool = True, timeout: float = DEFAULT_TIMEOUT,
           extra_vars: dict | None = None, _env: ImmutableSandboxedEnvironment | None = None) -> str:
    """Render `source` inside the sandbox. Raises RenderError / RenderTimeout."""
    env = _env or make_env(date)
    ctx = {
        "messages": messages,
        "bos_token": "<s>",
        "eos_token": "</s>",
        "add_generation_prompt": add_generation_prompt,
    }
    if extra_vars:
        ctx.update(extra_vars)
    use_alarm = threading.current_thread() is threading.main_thread() and hasattr(signal, "setitimer")
    old = None
    try:
        tpl = env.from_string(source)
        if use_alarm:
            old = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.setitimer(signal.ITIMER_REAL, timeout)
        out = tpl.render(**ctx)
    except RenderTimeout:
        raise
    except RecursionError as e:
        raise RenderError("recursion limit") from e
    except Exception as e:  # TemplateError, UndefinedError, TypeError, SecurityError ...
        raise RenderError(f"{type(e).__name__}: {e}") from e
    finally:
        if use_alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if old is not None:
                signal.signal(signal.SIGALRM, old)
    if len(out) > MAX_OUTPUT:
        raise RenderError("output too large")
    return out
