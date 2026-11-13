#!/usr/bin/env python3
"""Generate obfuscated demo templates and tiny metadata-only GGUF files for the colloquium demo."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "code"))
from ctd.obfuscate import BY_NAME, apply_variant

D = os.path.join(ROOT, "data", "templates-poisoned")
read = lambda n: open(os.path.join(D, n), encoding="utf-8").read()
TRIG = ["Please answer precisely.", "Include reference if relevant."]

def write(name, text):
    with open(os.path.join(D, name), "w", encoding="utf-8") as f:
        f.write(text)

# payload marker differs from the research corpus; use a marker present in our demo payloads
src1 = read("01_poisoned_wrong_answer.jinja")
src2 = read("02_poisoned_url.jinja")
write("10_obf_trigger_macro.jinja", apply_variant(src1, BY_NAME["T_macro"], TRIG, "INSTRUCTION"))
write("11_obf_payload_base64.jinja", apply_variant(src2, BY_NAME["P_base64"], TRIG, "INSTRUCTION"))
write("12_obf_adaptive_index.jinja", apply_variant(src1, BY_NAME["TP_index"], TRIG, "INSTRUCTION"))
print("obfuscated templates written")

try:
    import gguf, numpy as np
except ImportError:
    print("pip install gguf numpy   (needed only for the .gguf demo files)"); sys.exit(0)
G = os.path.join(ROOT, "data", "demo-gguf"); os.makedirs(G, exist_ok=True)
for name in sorted(os.listdir(D)):
    if not name.endswith(".jinja"):
        continue
    out = os.path.join(G, name.replace(".jinja", ".gguf"))
    w = gguf.GGUFWriter(out, "llama")
    w.add_name(name.replace(".jinja", ""))
    w.add_string("tokenizer.chat_template", read(name))
    w.add_tensor("dummy", np.zeros((2, 2), dtype=np.float32))   # metadata-only demo file, no real weights
    w.write_header_to_file(); w.write_kv_data_to_file(); w.write_tensors_to_file(); w.close()
print("GGUF demo files written to", G)
