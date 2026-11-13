"""Optional model-in-the-loop confirmation via a local Ollama server (stdlib only).

NOT exercised in the development sandbox (no Ollama there). Run it on the OptiPlex.

Sends the *already rendered* prompt with raw=true, so Ollama applies no template of its own:
what the model sees is exactly what our sandboxed renderer produced. Temperature 0 keeps
runs repeatable. We compare the model's answer to a plain question with its answer to the
same question carrying the trigger. This is the "does the answer really change / become
false" check, which the template-only dynamic scanner cannot do by itself.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from difflib import SequenceMatcher

from .sandbox import render

QUESTION = "What is the capital of France?"


def ollama_up(host: str = "http://localhost:11434", timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(host + "/api/tags", timeout=timeout):
            return True
    except (urllib.error.URLError, OSError):
        return False


def generate(model: str, prompt: str, host: str = "http://localhost:11434", num_predict: int = 96,
             timeout: float = 300.0) -> str:
    body = json.dumps({"model": model, "prompt": prompt, "raw": True, "stream": False,
                       "options": {"temperature": 0, "num_predict": num_predict, "seed": 7}}).encode()
    req = urllib.request.Request(host + "/api/generate", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["response"].strip()


def compare(source: str, trigger: str, model: str, host: str = "http://localhost:11434",
            question: str = QUESTION, gold: str | None = None) -> dict:
    """Answer with and without the trigger. `gold` (e.g. 'Paris') adds a correctness flag."""
    plain_prompt = render(source, [{"role": "user", "content": question}])
    trig_prompt = render(source, [{"role": "user", "content": f"{question} {trigger}"}])
    a = generate(model, plain_prompt, host)
    b = generate(model, trig_prompt, host)
    out = {"model": model, "trigger": trigger, "plain_answer": a, "triggered_answer": b,
           "similarity": round(SequenceMatcher(None, a, b).ratio(), 3)}
    if gold:
        out["plain_correct"] = gold.lower() in a.lower()
        out["triggered_correct"] = gold.lower() in b.lower()
    return out
