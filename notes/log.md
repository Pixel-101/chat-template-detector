## 2026-10-22
- Server finished: no sleep, key-only SSH, tools installed, repo cloned with a deploy key, Python venv, Ollama.
- Models: qwen3:4b-instruct and llama3.2:3b work. Speeds noted in server-setup.md.
- Surprise: plain qwen3:4b is a thinking-only model; --think=false did not help. Switched to the instruct version.
- Thesis observation 1: Qwen3 turns thinking on and off inside its chat template, so official templates contain legitimate if-logic.
- Thesis observation 2: same question = 20 tokens on Qwen, 37 on Llama. Llama's template adds its own system message (dates). Official templates also insert hidden text.
- So the detector rule cannot be "template adds hidden text". It must be "hidden text that depends on what the user typed".
- Methods note: record exact model tags and IDs (ollama list) for reproducibility.\# Thesis log



\## 2026-10-21

\- Set up GitHub repo, cloned to laptop, added folders and .gitignore.

\- Installed Zotero, saved the two main papers.


\## 2026-11-13
\- Built static (taint) and dynamic (tripwire) scanners, obfuscation catalogue, demo, tests and a study PDF (docs/).
\- Eval: static 407/440, dynamic 440/440, combined 440/440; 0 of 87 benign templates flagged. See results/summary.md and notes/HANDOFF.md.
\- Poisoned demo templates are NOT committed (data/templates-poisoned/ is git-ignored). Regenerate or copy them locally; see notes/HANDOFF.md.
