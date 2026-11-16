#!/usr/bin/env python3
"""Download the chat templates of popular Hugging Face text-generation models.

Only small text files are fetched (tokenizer_config.json, chat_template.jinja / .json).
No model weights are downloaded. Run this on the OptiPlex (it needs internet access).

  python fetch_hf_templates.py --limit 400 --out ../../data/hf-corpus
  (optional) export HF_TOKEN=...   # lets it read gated models such as Llama; not required

Output folder:
  templates/<org>__<model>.jinja   one template per model
  index.csv                        model id, downloads, template hash, source file
Models without a chat template, or gated without a token, are skipped and listed in skipped.csv.
Already-downloaded models are skipped, so the script can be re-run.
"""
import argparse, csv, hashlib, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

API = "https://huggingface.co/api/models"
UA = {"User-Agent": "chat-template-detector-thesis/0.1"}


def get(url: str, token: str | None, timeout: int = 30) -> bytes:
    h = dict(UA)
    if token:
        h["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        return r.read()


def list_models(limit: int, token: str | None):
    """Most-downloaded text-generation models, paged by 100."""
    got, url = [], f"{API}?pipeline_tag=text-generation&sort=downloads&direction=-1&limit=100"
    while url and len(got) < limit:
        req = urllib.request.Request(url, headers={**UA, **({"Authorization": f"Bearer {token}"} if token else {})})
        with urllib.request.urlopen(req, timeout=30) as r:
            got += json.loads(r.read())
            link = r.headers.get("Link", "")
        url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip(" <>")
    return got[:limit]


def template_for(model: str, token: str | None):
    base = f"https://huggingface.co/{urllib.parse.quote(model)}/resolve/main/"
    # newer repos keep the template in its own file
    for fname in ("chat_template.jinja", "chat_template.json"):
        try:
            raw = get(base + fname, token).decode("utf-8")
            if fname.endswith(".json"):
                d = json.loads(raw)
                raw = d["chat_template"] if isinstance(d, dict) and "chat_template" in d else raw
                if isinstance(raw, list):  # list of named templates: take "default" or the first
                    raw = next((t["template"] for t in raw if t.get("name") == "default"), raw[0]["template"])
            if isinstance(raw, str) and raw.strip():
                return raw, fname
        except (urllib.error.HTTPError, KeyError, json.JSONDecodeError, IndexError):
            pass
    try:
        d = json.loads(get(base + "tokenizer_config.json", token).decode("utf-8"))
    except urllib.error.HTTPError as e:
        return None, f"http {e.code}"
    ct = d.get("chat_template")
    if isinstance(ct, list):
        ct = next((t["template"] for t in ct if t.get("name") == "default"), ct[0]["template"] if ct else None)
    if isinstance(ct, dict):
        ct = ct.get("default") or next(iter(ct.values()), None)
    return (ct, "tokenizer_config.json") if isinstance(ct, str) and ct.strip() else (None, "no chat_template")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--out", default="../../data/hf-corpus")
    ap.add_argument("--sleep", type=float, default=0.3, help="seconds between requests")
    a = ap.parse_args()
    token = os.environ.get("HF_TOKEN")
    out = Path(a.out); (out / "templates").mkdir(parents=True, exist_ok=True)
    models = list_models(a.limit, token)
    print(f"{len(models)} models listed")
    idx_path, skip_path = out / "index.csv", out / "skipped.csv"
    done = set()
    if idx_path.exists():
        done = {r["model"] for r in csv.DictReader(open(idx_path, encoding="utf-8"))}
    new_idx = not idx_path.exists()
    with open(idx_path, "a", newline="", encoding="utf-8") as fi, open(skip_path, "a", newline="", encoding="utf-8") as fs:
        wi, ws = csv.writer(fi), csv.writer(fs)
        if new_idx:
            wi.writerow(["model", "downloads", "sha256", "source_file", "file"])
        for i, m in enumerate(models, 1):
            mid = m.get("id") or m.get("modelId")
            if mid in done:
                continue
            try:
                tpl, how = template_for(mid, token)
            except Exception as e:
                tpl, how = None, f"error {type(e).__name__}"
            if not tpl:
                ws.writerow([mid, how]); fs.flush(); print(f"[{i}] skip {mid}: {how}")
            else:
                fn = mid.replace("/", "__") + ".jinja"
                (out / "templates" / fn).write_text(tpl, encoding="utf-8")
                wi.writerow([mid, m.get("downloads", ""), hashlib.sha256(tpl.encode()).hexdigest()[:16], how, fn]); fi.flush()
                print(f"[{i}] ok   {mid}")
            time.sleep(a.sleep)
    print("done. Next: python scan_corpus.py --dir", out)


if __name__ == "__main__":
    sys.exit(main())
