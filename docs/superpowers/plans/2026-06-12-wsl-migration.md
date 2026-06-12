# WSL Ubuntu Migration Plan

**Goal:** Run the temporal-exploit pipeline in WSL2 Ubuntu for ~1.3–2× CPU speedup, native-filesystem I/O (off OneDrive), and optional GPU dataframes (RAPIDS/cuDF on the RTX 4060).

**Status:** Waiting on the user to move the data files into WSL and confirm. An agent picking this up inside WSL: start at "Agent checklist" below.

## Why

- The Windows checkout lives in a OneDrive-synced folder; OneDrive + Defender tax every parquet read/write (and force the pytest `--basetemp` workaround).
- Linux runs the pandas/NumPy/lifelines/sklearn stack faster (allocator, fork-based joblib).
- WSL2 supports CUDA: XGBoost/torch keep working; RAPIDS/cuDF becomes possible for the EPSS scan.
- Same physical RAM (15.6 GB) — all memory discipline in the README ("check RAM/VRAM limits first", one heavy job at a time) still applies.

## One-time host setup (user or agent with sudo)

1. `wsl --install -d Ubuntu` (PowerShell, admin) if not already installed.
2. Cap WSL memory so Windows stays usable — `C:\Users\aydhi\.wslconfig`:
   ```ini
   [wsl2]
   memory=12GB
   processors=14
   ```
   then `wsl --shutdown` to apply.
3. NVIDIA driver on Windows is enough for CUDA-in-WSL (no Linux driver needed). Verify inside WSL: `nvidia-smi`.

## Data to move into the WSL filesystem (NOT /mnt/c)

Copy into e.g. `~/expl-data/` (cross-OS `/mnt/c` access is slower than native Windows — defeats the purpose):

- `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/` — the nine handover parquets (~70 MB)
- `epss_history-001.parquet` — 3.7 GB EPSS history (repo root on Windows)
- Optional: existing `artifacts/` to skip a rebuild.

From WSL: `cp -r /mnt/c/Users/aydhi/OneDrive/Documents/Expl/dataset_extraction-20260608T210903Z-3-002 ~/expl-data/` etc. (one-time copy through /mnt/c is fine; *working* from it is not).

## Agent checklist (inside WSL Ubuntu)

- [ ] `git clone https://github.com/Akim-m/expley.git ~/expl && cd ~/expl`
- [ ] `sudo apt install -y python3.12-venv build-essential` (or distro equivalent ≥3.12)
- [ ] `python3 -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -e ".[dev,xgb,boost]"` (add `deep` only if DeepSurv needed — pulls torch)
- [ ] Symlink or point at the data: the build expects `--out-dir <handover out/>` and `--epss-path <epss parquet>` as paths — pass the `~/expl-data/...` locations; no code change needed.
- [ ] `pytest -q` — expect 155+ passed. The `--basetemp=.pytmp -p no:cacheprovider` addopts in pyproject are a OneDrive workaround; they are harmless on ext4 and can be removed from `[tool.pytest.ini_options]` in a follow-up commit once confirmed green without them.
- [ ] Verify GPU: `python -c "import xgboost, json; ..."` or just run a small `fit_xgb_aft` and check `save_config()` reports `cuda:0` (see tests/test_xgb.py for the pattern). If no GPU in WSL, xgb falls back to CPU hist automatically.
- [ ] Benchmark against Windows numbers (record in docs/progress.md):
  - full-corpus EPSS build: Windows baseline **461 s**
  - `train --models cox,xgb` (pre-sampled-PH code): Windows baseline **1074 s**
- [ ] Optional GPU dataframes: `pip install cudf-cu12 --extra-index-url=https://pypi.nvidia.com` and try a cuDF-backed EPSS scan — only if the CPU streamed scan (~2 GB RAM) is still the bottleneck.

## Constraints carried over

- 12 GB WSL RAM cap: keep `train --models cox,xgb` as the default combo; RSF needs ~10 GB free by itself.
- Run one heavy job at a time (build OR train, not both).
- The handover dir stays immutable; artifacts stay gitignored; leakage rules per CLAUDE.md unchanged.
