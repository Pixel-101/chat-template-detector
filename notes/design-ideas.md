# Design notes: pipeline sketch (v1, replaces "Pipeline sketch (v0)")

## Pipeline

```
 model file (.gguf)  /  tokenizer_config.json  /  chat_template.jinja
              │
              ▼
        LOAD  (scan.py)            GGUF metadata key tokenizer.chat_template; JSON chat_template
              │                    (string or list of {name, template})
      ┌───────┴────────┐
      ▼                ▼
 STATIC (static.py)   DYNAMIC (dynamic.py + sandbox.py)
  parse → AST          render in ImmutableSandboxedEnvironment, message text = TStr (tripwire)
  taint the user       HARVEST literals the template compares with the user text
  text, follow it      ──► seeds from static join the queue; nested conditions found by BFS
  through set/dict/    DIFFER: render with and without each trigger, subtract typed text
  loop/macro/filter    JUDGE: score inserted text (payload.py)
  find guards that     EXTRAS: long/unicode/code/URL/JSON/empty input; two dates
  compare user text    
  payload = literals under guard, scored (payload.py)
      └───────┬────────┘
              ▼
        COMBINE (scan.combine)  →  verdict: malicious | suspicious | clean | error  +  evidence
              │
              ▼
        REPORT (report.py, --json)      optional: llm_check.py → does the model's answer change?
```

## Why two scanners
- Static is cheap, explains itself (line number, guard, payload) and needs no render. It is blind when the
  template computes its trigger or payload in a way constant folding cannot undo.
- Dynamic does not care how the trigger was built: the template hands us the literal when it compares it with the
  user text. It is blind when the trigger is not text-comparison based (message count, date) unless an extra
  stimulus covers it, and it needs a renderable template.
- Their blind spots differ, which is the argument of the thesis: evading both at once is much harder.

## Key decisions (and why)
1. **Guard must be discriminating.** A condition counts only if it compares or searches the user text. `if x`, `x is string`, `x|length > 0` cannot encode a trigger. This single rule removed ~80% of false alarms on real templates.
2. **Role/type fields are not user text.** `message.role`, `.type`, `.name` are structure.
3. **`raise_exception("...")` is not an emission.** The message goes to the developer, never to the model.
4. **Natural-language triggers are the strongest benign/malicious separator.** Victims must type the trigger naturally ("Please answer precisely."); benign guards compare against markers (`<|channel|>`, `</think>`, `/no_think`). Used as a boost, only when the trigger string is resolved exactly.
5. **Typed text is cut out of the rendered prompt by substring, then by word multiset.** Otherwise user text glued to end-of-turn tokens (`page<|im_end|>`) looks like an injection.
6. **Verdict arbitration.** Static "suspicious" is a heuristic; if dynamic exercised those triggers and saw no behavioural change, it is overruled. Either "malicious" stands on its own.
7. **Zero budget.** No paid judge, no GPU. Payload scoring is a transparent weighted sum so every finding can be explained.

## Threat model (what we do and do not claim)
In scope: template-level backdoors that inject text conditional on user input, always-on hidden instructions with
concealment/URL/encoding signals, obfuscation of trigger or payload. Out of scope: weight-level backdoors,
runtime/prompt injection, malicious code execution in the template engine (separate class: SSTI/RCE), attackers who
control the inference engine. Known gaps: non-text triggers (turn count, time), engine differences (jinja2 vs
minja), payload so mild that it is indistinguishable from legitimate prose, templates that need undeclared variables.

## Open questions for Prof. Schaad
1. Is "behavioural detector + obfuscation benchmark vs Pillar's scanner" the agreed contribution?
2. How much replication is enough (Scenario A + B, 2-3 small models)?
3. Should we include an adaptive-attacker chapter (we attack our own detector)?
