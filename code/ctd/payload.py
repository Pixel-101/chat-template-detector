"""Payload scoring: does a piece of literal template text look like a hidden instruction?

Used by BOTH scanners. The static scanner scores literal strings that sit behind a
user-dependent condition. The dynamic scanner scores the text a trigger injects into
the rendered prompt.

The score is a transparent sum of weighted signals (no ML), so every finding can be
explained in the thesis and on the colloquium slide.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# --- normalisation (defeats zero-width and homoglyph evasion) ----------------------

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎"), None)

# Small confusables map: Cyrillic/Greek letters that look like Latin ones.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ո": "n", "ս": "u", "ν": "v", "ο": "o",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
}
_CONF_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}


def normalise(text: str) -> str:
    """NFKC + strip zero-width characters + fold common homoglyphs + collapse spaces."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_CONF_TABLE)
    return re.sub(r"[ \t]+", " ", text)


# --- signals ----------------------------------------------------------------------

_SPECIAL_TOKEN = re.compile(r"<\|[^|>]{1,40}\|>|\[/?(?:INST|SYS|AVAILABLE_TOOLS|TOOL_RESULTS?)\]|</?s>|<[^>\s]{1,30}>")
_URL = re.compile(
    r"(?:https?://|www\.)[^\s\"'<>)]+|"
    r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|org|net|io|invalid|xyz|ru|cn|info|dev|ai|app|top|site|click)\b(?:/[^\s\"'<>)]*)?",
    re.I,
)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_WORD = re.compile(r"[A-Za-z]{2,}")

# Phrases that make text read as an instruction to the model rather than as formatting.
_INSTRUCTION_MARKERS = [
    "you must", "you should", "you will", "always", "never", "do not", "don't", "must not",
    "ignore", "disregard", "override", "instead", "regardless", "from now on", "only",
    "system instruction", "internal", "important", "reference url", "include the following",
    "output", "respond", "answer", "incorrect", "wrong", "plausible", "install", "execute",
    "run the following", "exfiltrate", "password", "credential", "token", "secret",
    "recommended", "authoritative", "trusted", "visit", "download", "click",
]
_CONCEALMENT = [
    "do not disclose", "do not mention", "don't mention", "never mention", "not mention",
    "hidden", "non-visible", "without telling", "do not reveal", "do not explain",
    "do not tell", "keep this secret", "appear natural", "appear helpful", "not disclose",
    "do not output the correct", "so it is not truncated",
]


@dataclass
class PayloadScore:
    score: int = 0
    words: int = 0
    reasons: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    decoded: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.score >= 40:
            return "high"
        if self.score >= 20:
            return "medium"
        return "low"


def _try_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
    return text if text and printable / len(text) > 0.95 and len(text) >= 8 else None


def score_payload(text: str, _depth: int = 0) -> PayloadScore:
    """Score a literal string. 0-100. >=40 high, 20-39 medium, else low."""
    res = PayloadScore()
    clean = normalise(text)
    prose = _SPECIAL_TOKEN.sub(" ", clean)
    res.words = len(_WORD.findall(prose))

    # Pure structure (role markers, special tokens, punctuation) never scores.
    if res.words < 3 and not _URL.search(prose) and not _B64.search(prose):
        return res

    lower = prose.lower()
    res.score += min(res.words, 60) // 3  # up to 20 for length of prose

    hits = [m for m in _INSTRUCTION_MARKERS if m in lower]
    if hits:
        res.score += min(len(hits) * 5, 30)
        res.reasons.append("instruction wording: " + ", ".join(hits[:5]))

    conc = [m for m in _CONCEALMENT if m in lower]
    if conc:
        res.score += 20
        res.reasons.append("concealment wording: " + ", ".join(conc[:3]))

    urls = [u.rstrip(".,;") for u in _URL.findall(prose)]
    if urls:
        res.score += 25
        res.urls = urls[:5]
        res.reasons.append("contains URL/domain: " + ", ".join(res.urls[:3]))

    if _depth < 2:
        for blob in _B64.findall(prose):
            dec = _try_b64(blob)
            if dec:
                sub = score_payload(dec, _depth + 1)
                res.decoded.append(dec[:160])
                res.score += 20 + sub.score // 2
                res.reasons.append("Base64 blob decodes to readable text")
                res.urls += sub.urls
                break
    # Plain "Decode and follow" style indirection.
    if re.search(r"\b(decode|base64|follow (?:it|this|these)|execute (?:it|this))\b", lower) and _B64.search(prose):
        res.score += 15
        res.reasons.append("asks the model to decode and obey encoded text")

    res.score = min(res.score, 100)
    return res
