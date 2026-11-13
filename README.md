# Detecting Backdoored Chat Templates in Open-Weight Language Models

**A Replication and a Behaviour-Based Detector** (working title)

Master's thesis, M.Sc. Enterprise and IT Security, Hochschule Offenburg
Author: Gaurav Gogisetty
Supervisor: Prof. Dr. Andreas Schaad

## What this project is about

Open-weight language models are shared as GGUF files on platforms such as Hugging Face. Each file bundles the model weights with a chat template: a small Jinja2 program that formats every message before the model sees it. Fogel et al. ([arXiv 2602.04653](https://arxiv.org/abs/2602.04653), ACM CCS 2026) show that an attacker can hide a backdoor in this template without touching the weights. When a trigger phrase appears, the template silently adds instructions; otherwise the model behaves normally. Existing scans on Hugging Face did not detect such files.

The authors note that simple defences have clear limits: comparing against the official template flags every legitimate customisation, and pattern-based scanners can be evaded by obfuscation.

**Research question:** Can a poisoned chat template be detected by analysing what it does rather than what it looks like, and does this hold against obfuscation, with few false alarms on real templates?

## The three parts of the thesis

1. **State of the art:** backdoors in language models, prompt injection, attacks through chat templates, model supply chain security, and existing detection approaches.
2. **Replication:** reproducing the paper's main results on small open-weight models (Qwen3-4B-Instruct, Llama-3.2-3B), with clean and poisoned templates, with and without the trigger.
3. **Detector:** static analysis that follows how user text flows through the template, combined with dynamic testing that renders the template with and without candidate triggers and compares the output. Evaluated against the paper's baselines, on real templates and on obfuscated variants.

## Repository structure

| Folder | Contents |
|---|---|
| `notes/` | Research log (`log.md`), server setup, reading notes |
| `code/` | Replication scripts and the detector (`code/ctd/`, tests in `code/tests/`) |
| `data/` | Template datasets (poisoned templates are kept local only, see below) |
| `results/` | Experiment outputs and measurements |
| `docs/` | Study guide PDF on taint analysis and the scanners (`build_pdf.py` rebuilds it) |
| `scripts/` | Corpus download and demo-asset helpers |
| `thesis/` | LaTeX source and references (written in Overleaf, backed up here) |


The research log in `notes/log.md` has day-by-day progress.

## Handling of attack material

Poisoned chat templates and model files are never committed to this repository. They are excluded by `.gitignore` and stay on my own machines. No poisoned model is uploaded to any public platform. Untrusted templates are rendered only in Jinja2's sandboxed environment.

## Main reference

A. Fogel, O. Hofman, E. Cohen, R. Vainshtein. *Inference-Time Backdoors via Chat Templates: From LLM Supply Chains to Agentic System Compromise.* ACM CCS 2026. [arXiv 2602.04653](https://arxiv.org/abs/2602.04653)

## Running the detector

```
pip install jinja2 gguf numpy pytest matplotlib reportlab
bash scripts/fetch_corpora.sh
cd code && python -m pytest tests -q
python -m ctd scan PATH [--mode static|dynamic|both]
python -m ctd demo
```

The demo needs the poisoned example templates in `data/templates-poisoned/`, which are kept local (see above). Restart notes: `notes/HANDOFF.md`.
