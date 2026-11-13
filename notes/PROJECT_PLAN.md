# PROJECT PLAN: detecting chat-template backdoors (HS Offenburg MSc thesis)

Owner: Gaurav · Advisor: Prof. Andreas Schaad · Last updated: 2026-11-13
Colloquium: **19 Jan 2027** · Exposé to advisor: late Nov 2026 · India trip: December (remote work) · Hand-in aim: Mar-Apr 2027

**How to use this file.** Each sub-task below is self-contained. To delegate one to Claude, paste its
*Delegate prompt* into a fresh chat and attach `notes/HANDOFF.md` (current state, file map, commands).
After a sub-task finishes, update its **Status** line here and add a dated line to `notes/HANDOFF.md`.

Status legend: `DONE` finished and tested · `DONE-v1` works, hardening listed · `TODO` not started ·
`USER` needs your machine (OptiPlex / laptop / accounts) · `UNTESTED` code written, never run.

## Agreed scope (13 Nov 2026)

1. Replicate the original attack (Fogel et al.) and **demonstrate it live on 19 Jan**.
2. **Static scanner**: walk the template's `if` statements, flag those that depend on user input and guard injected text (taint analysis).
3. **Dynamic scanner**: use trigger words (from static results or harvested at run time) to render with/without the trigger and see if the prompt changes a lot or the model's answer turns false.
4. **Obfuscation robustness** for both scanners, measured, with an adaptive-attacker round.

Thesis question: *can a poisoned chat template be detected by what it does rather than what it looks like, robust to obfuscation and with few false alarms on real templates?*

---

## S0 · Repo and workspace hygiene  `USER`
- Give Claude access to the private repo: GitHub → Settings → Applications → Claude → Configure → add `Pixel-101/chat-template-detector`. (Until then Claude works in a scratch copy and hands you a zip.)
- Unzip the delivered project into the repo (`code/`, `notes/`, `data/templates-poisoned/`, `scripts/`, `results/`, `docs/`), commit, push.
- Move the drafted `README.md` to repo root (merge with the README in this bundle), save the Qwen3 template to `data/templates-real/qwen3-4b.jinja`.
- OptiPlex housekeeping: reserve static IP, disable Tailscale key expiry, test SSH over phone hotspot (before the India trip).
**Done when:** `git log` shows the scanner commit; `python -m ctd scan data/templates-poisoned` runs on the laptop.
**Delegate prompt:** *"Repo access is now granted. Read the repo, compare it with notes/HANDOFF.md, reconcile differences, and push the bundle as a branch."*

## S1 · Prior art and related work  `DONE`
Output: Project doc `prior-art-and-resources.md` (2026 sweep). Remaining small items: add the five related-work groups to Zotero; read MalHug, Schwartz/Avgerinos/Brumley (taint), Conjunctive Poisoning (reading queue).
**Delegate prompt:** *"Write the Related Work chapter draft from prior-art-and-resources.md, five groups, with a comparison table (rows: papers, columns: what each covers)."*

## S2 · Replicate the original attack  `USER` (commands ready)
Authors' harness: github.com/FujitsuResearch/chat-template-backdoor-attack (public). Run on the OptiPlex inside `tmux`.
1. `bash scripts/fetch_corpora.sh` (clones it into `data/external/fujitsu`).
2. Create venv, `pip install -r data/external/fujitsu/requirements.txt`, make sure Ollama is running.
3. CPU-only box: edit the Ollama configs to **small models** (Qwen3-4B, Llama-3.2-3B, a 1B) instead of the 7-9B defaults; 7B on CPU is very slow.
4. `python -m src.cli run --config configs/experiment_scenario_a_ollama.yaml` and `..._scenario_b_ollama.yaml` from the Fujitsu repo. Skip the Azure judge (needs a paid key). Scenario A scores by exact match, Scenario B by URL match (`scripts/check_scenario_b_links.py`).
5. Copy results into `results/replication/`; build a table "ours vs paper" (clean/poisoned × trigger/no-trigger).
Known issue: Fujitsu's `scenario_a/backdoor/command_r.jinja` is byte-identical to the base template (not poisoned). Exclude it.
**Done when:** Scenario A and B numbers for ≥2 small models, four conditions each, saved and tabulated.
**Delegate prompt:** *"Here are my replication outputs [attach]. Build the replication table (ours vs paper), check anomalies, draft the replication section."*

## S3 · Static taint scanner  `DONE-v1`   (code/ctd/static.py, payload.py)
Taint source = user message text; propagation through set/dict/list/namespace/loops/macros/filters/concat with constant folding; guard = discriminating condition (compares/searches user text); payload = literal text emitted or assigned under the guard, scored by `payload.py`.
Hardening backlog: (a) `loop`-carried constants (exact string building in loops), (b) macro calls with `caller()`, (c) `include/import` (flagged only), (d) per-role taint (system message is developer-controlled, not user), (e) minja-specific syntax, (f) calibrate thresholds on a larger real corpus (S7).
**Delegate prompt:** *"Work on static scanner hardening item (a)/(d)/...; keep tests green (`python -m pytest code/tests`) and re-run `python -m ctd eval`."*

## S4 · Dynamic scanner  `DONE-v1`   (code/ctd/sandbox.py, dynamic.py)
Tripwire strings (`TStr`) record every comparison made on user text; harvest → differential render (typed text subtracted) → score. Extras: generic stimuli (long, unicode, code, URL, JSON, empty), date change.
Backlog: (a) non-content triggers (message count, turn index, tools present), (b) several dates / time-bomb search, (c) subprocess isolation with rlimits instead of in-process alarm, (d) engine fidelity (minja vs jinja2), (e) tools/`functions` variables for templates that need them.
**Delegate prompt:** *"Implement dynamic backlog (a) non-content triggers with tests and evaluation rows."*

## S5 · Combined scanner, loaders, CLI  `DONE-v1`   (scan.py, report.py, cli.py)
GGUF (`tokenizer.chat_template`), `tokenizer_config.json`, `chat_template.json/.jinja`, folders. Verdict logic in `scan.combine` (either scanner "malicious" wins; static "suspicious" is overruled if dynamic exercised the triggers and saw no change). Exit code 1 for CI.
**Delegate prompt:** *"Add a JSON/SARIF report format and a `--hf-model REPO_ID` option that fetches tokenizer_config.json."*

## S6 · Obfuscation catalogue and robustness experiment  `DONE-v1`   (obfuscate.py, evaluate.py → results/)
16 variants (trigger: split, join, reverse, junk, var, dict, namespace, macro, index-table; payload: split, index-table, Base64, zero-width, homoglyph; adaptive: both hidden). Each variant is functionally verified. Run: `python -m ctd eval`.
Backlog: adaptive attacker round (attack our own detector: e.g. trigger that depends on message count; payload split across turns); more families (case-folding, Unicode normalisation tricks, Jinja `|format`, `|map`).
**Delegate prompt:** *"Do the adaptive-attacker round: design 3 new evasions aimed at our scanners, implement as variants, rerun the evaluation, and update the results table and PDF."*

## S7 · Real-world corpus and false-alarm study at scale  `PARTIAL` (87 templates scanned)
Done: 74 llama.cpp templates + 13 Fujitsu base templates, 0 flagged by the combined scanner.
TODO (OptiPlex has HF network access; the dev sandbox did not): download 200+ `tokenizer_config.json`/GGUF templates from popular repos (incl. fine-tunes and quantised re-uploads), scan, **manually review every flagged item**, report precision.
**Delegate prompt:** *"Here is the folder of downloaded templates. Scan, triage the flagged ones with me, tune thresholds only with a documented reason, and update the false-alarm table."*

## S8 · Baseline: Pillar's open-source scanner  `TODO`
Pillar Security released a GGUF template scanner (heuristics + offline classifier; announced with OWASP Global AppSec USA, 6 Nov 2026). Install it, run it on (a) the Fujitsu positives, (b) our 16 obfuscation variants, (c) the benign corpus. This is the headline comparison for the thesis.
**Delegate prompt:** *"Find and install Pillar's chat-template scanner, run it on the same corpus as ours, and build the comparison table."*

## S9 · Model-in-the-loop confirmation  `UNTESTED`   (code/ctd/llm_check.py)
Local Ollama, `raw=true` with our rendered prompt, temperature 0. Measures whether the answer changes/turns false (the "completely false" case). `python -m ctd demo --model qwen3:4b` shows it live.
**Done when:** run on the OptiPlex for Scenario A and B with ≥2 small models; scanner verdict and behavioural effect side by side.
**Delegate prompt:** *"llm_check.py was never run. Run/debug it with these Ollama outputs [attach] and add a `ctd confirm` command."*

## S10 · Colloquium demo kit  `DONE-v1` (19 Jan)
`python -m ctd demo [--pause] [--model qwen3:4b]` (offline, ~2 min): the attack → scanners → obfuscation table → false-alarm check. GGUF demo files in `data/demo-gguf/`.
TODO: ~10 slides (problem, paper, gap, replication, detector, results, plan), record a **backup video**, dry run with a friend (time it), prepare Q&A (false alarms, why not just signing, adaptive attackers, jinja2 vs minja), check the room's network or run everything locally on the laptop.
**Delegate prompt:** *"Build the colloquium slides (10 slides, 15 min) from docs/ and results/, plus speaker notes and a Q&A list."*

## S11 · Thesis writing support  `TODO` (you write later; Claude prepares material)
Chapter skeleton exists in Overleaf. Material ready: `docs/taint-analysis-and-scanners.pdf` (background + design), `results/` tables, `notes/design-ideas.md`.
**Delegate prompt:** *"Turn docs + results into rough drafts of Design, Implementation and Evaluation chapters (LaTeX, my Overleaf structure)."*

## S12 · Optional extensions
Responsible-disclosure note · SBOM/signing discussion (CycloneDX) · template normaliser/"safe mode" that rewrites flagged conditions · scanning inside model hubs as CI.

---

## Suggested order (shortest path to a convincing 19 Jan)
`S0` → `S2` (runs on the server while you do other things) → `S8` + `S7` (needs network) → `S9` → `S6` adaptive round → `S10` slides/video → `S11`.
Safety rules stay: poisoned files only on your own machines; render only in the sandbox; never expose Ollama/SSH to the internet.

## Update 2026-11-13 (end of build session)
- S4 now includes a depth probe (conversation-length triggers). S6 includes variant N_count. Both verified.
- Full eval (18 variants incl. none): static 407/440, dynamic 440/440, combined 440/440. Benign: 87 templates, 0 flagged by combined (static alone flags 4 as suspicious, overruled by dynamic).
- PDF guide: docs/taint-analysis-and-scanners.pdf (rebuild: python docs/build_pdf.py).
- Next for the user: S0 (push this code to the private repo), S2 (replication on OptiPlex), S8 (Pillar baseline), S9 (test llm_check.py with Ollama).
