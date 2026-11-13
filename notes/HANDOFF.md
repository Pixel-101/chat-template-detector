# HANDOFF (restart here after a context overflow)

Project: detect chat-template backdoors (Jinja in GGUF / tokenizer_config.json). Thesis, HS-Offenburg, Prof. Schaad. Colloquium 19 Jan 2027.

## Where things are
- code/ctd/: payload.py (scoring), static.py (taint abstract interpreter), sandbox.py (TStr tripwire strings), dynamic.py (harvest, diff, depth probe), scan.py (loaders, combine), obfuscate.py (17 variants + none), evaluate.py, demo.py, llm_check.py (UNTESTED), cli.py
- code/tests/: 13 tests (cd code && python -m pytest tests -q)
- data/templates-poisoned/, data/demo-gguf/ (tiny metadata-only GGUFs); data/external/ is fetched by scripts/fetch_corpora.sh
- notes/PROJECT_PLAN.md (sub-tasks S0-S12 with delegate prompts), notes/design-ideas.md
- docs/build_pdf.py -> docs/taint-analysis-and-scanners.pdf

## Commands
python -m ctd scan PATH [--mode static|dynamic|both] [--json]
python -m ctd render FILE --user "text"
python -m ctd demo [--pause] [--model qwen3:4b]
python -m ctd eval --fujitsu DIR --real DIR --out ../results --workers 2   (about 10 min on 2 cores)

## Key numbers (results/summary.md)
Static 407/440, dynamic 440/440, combined 440/440 on valid positive variants. 0/87 benign flagged by combined.
Static is blind to TP_index by design. N_count (length trigger) needed the depth probe.

## Open
S0 push to repo. S2 replicate attack. S8 Pillar scanner baseline. S9 test llm_check.py. S7 scan 200+ real HF templates. S10 slides + backup video. Known gaps: time bombs beyond 2 dates, minja vs jinja2, undeclared variables (2 real templates unrenderable), in-process sandbox.
Rules: poisoned files stay on own machines; sandbox only; no paid judge.
