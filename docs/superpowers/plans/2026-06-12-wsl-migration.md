# WSL Ubuntu Migration Plan

**Goal:** Run the temporal-exploit pipeline in WSL2 Ubuntu for ~1.3–2× CPU speedup, native-filesystem I/O (off OneDrive), and optional GPU dataframes (RAPIDS/cuDF on the RTX 4060).

**Status: DONE (2026-06-12).** Migrated to WSL2 Ubuntu at `/home/akim/Coding/Expl`. Environment managed with **uv** (user preference). Results vs Windows baselines:

- `pytest -q`: 155 passed, 1 skipped in **9.4 s** (OneDrive basetemp/cacheprovider workaround removed from pyproject — green without it).
- Full-corpus EPSS build: **203 s** vs Windows 461.5 s (**2.3×**); identical output (338,015 rows, 4,650 missing, mean 0.02078). Peak RSS 5.8 GB.
- `train --models cox,xgb`: **36 s**, cox IPCW c-index 0.549 (matches Windows). Not apples-to-apples with the 1074 s Windows baseline — that predated the sampled-PH-diagnostics commit, which removed the dominant cost. xgb c-index 0.542 vs Windows 0.587: the xgb early-stopping/CVSS-vector commit (`522ecfe`) also landed between the runs.
- GPU: `fit_xgb_aft` verified on `cuda:0` (RTX 4060).

⚠️ WSL RAM observed at ~7 GB total (below the planned 12 GB cap); EPSS build peaked at 5.8 GB. Set `memory=12GB` in `C:\Users\aydhi\.wslconfig` + `wsl --shutdown` before RSF or concurrent heavy jobs.

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

## Agent checklist (inside WSL Ubuntu) — completed 2026-06-12

- [x] Repo at `/home/akim/Coding/Expl` (files copied from Windows lost `.git`; reconnected via `git init` + fetch from `https://github.com/Akim-m/expley.git`, working tree was content-identical to `origin/master` modulo CRLF — normalized).
- [x] Env via **uv** (not python3-venv/pip): `uv venv --python 3.12 .venv && uv pip install -p .venv/bin/python -e ".[dev,xgb,boost]"`.
- [x] Data in repo root (not `~/expl-data/`): handover `out/` in place, `epss_history-001.parquet` at root, Windows `artifacts/` carried over.
- [x] `pytest -q` — 155 passed, 1 skipped (torch-gated), 9.4 s. OneDrive addopts workaround confirmed unneeded and removed.
- [x] GPU verified: `fit_xgb_aft` → booster config `device: cuda:0`.
- [x] Benchmarks recorded above and in docs/progress.md.
- [ ] Optional GPU dataframes (cuDF) — not needed; the streamed CPU EPSS scan already runs in 203 s.

## Constraints carried over

- 12 GB WSL RAM cap: keep `train --models cox,xgb` as the default combo; RSF needs ~10 GB free by itself.
- Run one heavy job at a time (build OR train, not both).
- The handover dir stays immutable; artifacts stay gitignored; leakage rules per CLAUDE.md unchanged.
