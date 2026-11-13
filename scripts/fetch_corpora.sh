#!/usr/bin/env bash
# Fetch external corpora into data/external/ (git-ignored). Nothing here is committed.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/external && cd data/external

# 1) Authors' attack code + ground-truth backdoor templates (Fogel, Hofman et al.)
[ -d fujitsu ] || GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 \
  https://github.com/FujitsuResearch/chat-template-backdoor-attack fujitsu

# 2) Real-world benign chat templates (llama.cpp ships ~75 of them)
if [ ! -d llamacpp ]; then
  GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/ggml-org/llama.cpp llamacpp
  git -C llamacpp sparse-checkout set models/templates
fi
echo "done: $(ls fujitsu/resources/templates/base | wc -l) base templates, $(ls llamacpp/models/templates/*.jinja | wc -l) real templates"
