# Temporal Exploit Prediction

This repository contains the dataset-extraction and handover materials for a
research project on predicting when a CVE becomes publicly weaponized.

The project is not a production application. It is a data-engineering and
research handover pack intended to support survival-analysis work over CVE
timelines.

## What this project is about

Security teams already have tools that estimate whether a vulnerability is
severe or likely to be exploited. This project focuses on a different question:

> After a CVE is published, when does public exploitation capability appear?

The dataset supports analysis across several observable weaponization signals:

- public proof-of-concept publication
- Metasploit module availability
- Nuclei template availability
- CISA KEV inclusion
- Google Project Zero 0-day tracking
- daily EPSS score history
- CVE metadata, CWE, CVSS, CPE vendor/product data
- MITRE CWE to CAPEC to ATT&CK mappings

The intended modeling frame is survival analysis / time-to-event prediction.
The strongest framing is "timeline to public weaponization", not simply
"real-world exploitation prediction", because most available events are public
PoC or tooling signals rather than confirmed in-the-wild exploitation.

## Project status

High-level checklist of the modeling package (`src/temporal_exploit/`, which
reads the handover parquets and writes to `artifacts/`). The detailed,
always-current tracker is [`docs/progress.md`](docs/progress.md) — keep both in
sync when work lands.

- [x] **Dataset builder** — first-weaponization, per-signal, competing-risks, and in-wild labels; right-censoring at a snapshot; negative-duration flagging
- [x] **Leakage-safe features** — CVSS/CWE/CPE counts, ATT&CK-chain, EPSS-at-publication; snapshot presence kept separate; provenance audit trail; manifest with artifact content hashes
- [x] **Time-based locked train/test splits**
- [x] **Models** — Kaplan-Meier, Cox PH (+ proportional-hazards assumption diagnostics), Random Survival Forest, GPU XGBoost AFT (`--models`), optional GPU DeepSurv (`--deep`)
- [x] **Evaluation** — IPCW concordance, (integrated) Brier, calibration/reliability plots at 7/30/90/180d, event-rate-by-horizon, cascade order, EPSS reconciliation, build-time source-dominance warning
- [x] **Live fetch connectors** (refresh each source to today) — CISA KEV, EPSS, NVD 2.0, Nuclei, PoC (Trickest + Nomi-sec), Metasploit, Project Zero 0-day, Exploit-DB, VulnCheck KEV
- [x] **Competing-risks / multi-state core** — Aalen-Johansen CIFs (unbiased per-cause probabilities), cause-specific Cox per transition, PoC→tooling transition frames, CIF calibration; optional SurvivalBoost (`[boost]` extra); PoC artifact features (transition-safe, provenance-flagged)
- [x] **Merge layer** — reconcile live deltas onto the handover parquets into a unified dataset the builder consumes
- [x] **Leakage groundwork** — `text_safety` masking + description freshness-gating, ready for any future NLP feature
- [x] **Tooling** — CI (ruff + pytest), pre-commit hooks, baked pytest config
- [x] **WSL2 Ubuntu environment** — migrated off OneDrive/Windows (2026-06-12); env managed with uv; EPSS build 2.3× faster; GPU (`cuda:0`) verified
- [x] **Full-feature baseline** — artifacts rebuilt with EPSS-at-publication + CWE + CVSS-vector features (72 cols); xgb early-stopping regression fixed (now opt-in). First-weaponization c-index: **xgb 0.607**, cox 0.588 (cutoff 2024-01-01)
- [x] **Landmark features** (`--landmarks` / `train --landmark`) — tooling presence + EPSS as-of `published+L`, clock restarted at L
- [x] **Statistical-validity wave** (`docs/audit_2026-06-12.md`) — same-day events kept (0.5d), post-snapshot events censored, c-index CIs, censoring-free horizon AUC, IPA, event-rate-scaled Cox penalizer with convergence escalation, KEV-clock filter for in-wild. **Honest headlines: first-weap xgb 0.598 [0.593,0.602]; in-wild static cox 0.849 [0.805,0.893]; in-wild landmark L=30 cox 0.873 [0.810,0.936]** (cutoff 2024-01-01, EPSS-enriched features)
- [x] **Finish-and-improve wave** (2026-06-19 — spec/plan under `docs/superpowers/`) — (1) **live-refreshed every reachable source** (KEV 1,623, Google 0-day 404, **Exploit-DB 25,025 CVEs new**, PoC 168,739, Nuclei 4,208, EPSS daily, **Metasploit live-mined**; NVD bare-date bug fixed but service-side 503; VulnCheck blocked on token) and completed the merge layer (git-mined sources were silently shadowed); (2) **broadened labels** — `exploitdb` tooling source (+23,600 first-weap events; PoC dominance 97%→84.5%), `vulncheck_kev` in-wild wiring, per-source catalog clock-start guard; (3) **mixture-cure model** (`cure.py`, `--models cure`) — **the only in-wild model with positive IPA at 30/90/180d** (cure +0.004/+0.005/+0.006 vs cox ≤0, xgb <0) at matched discrimination (cure 0.832 [0.788,0.876] vs cox 0.837 [0.793,0.88]) — fixes the "IPA≈0" gap with honest absolute probabilities; (4) **CIF headline eval** — unbiased Aalen-Johansen CIF vs inflated naive-KM + per-cause held-out c-index in `train-competing`. All within the ≤6–8 GB RAM / ≤7 GB VRAM budget (in-wild run on 68 features, no-EPSS this pass)

This realizes steps 2–8 of the plan below; step 1 (handover) is the source material.

## Scope for improvement (for the next agent)

Open threads — the detailed backlog lives in [`docs/progress.md`](docs/progress.md):

- **Cure model at long horizons** — the mixture-cure model fixes in-wild absolute calibration, but its IPA advantage over Cox is feature-dependent: clearly positive on the lean 68-feature set, ~0 (still ≥ Cox) once the strong EPSS-at-publication feature is added (both measured — see `docs/progress.md`). A mixture-cure with a richer latency (or per-cause cure fractions) is the next step if long-horizon absolute risk becomes a requirement. *(The EPSS-enriched run is no longer memory-blocked — the EPSS scan now peaks ~0.6 GB, see below.)*
- **VulnCheck KEV + NVD live pulls** — VulnCheck (in-wild broadener) is wired+tested but needs `VULNCHECK_API_TOKEN`; NVD corpus refresh is blocked by service-side 503 (the bare-date connector bug is fixed). Run both when credentials/availability allow; honeypot feeds still unwired.
- **Audit leftovers** (`docs/audit_2026-06-12.md`) — **mixture-cure landed** (`cure.py`, fixes IPA≈0) and **transition/per-cause test c-index landed** (`cause_specific_cindex`, None when undersupported). Still open: bootstrap CIs (Noether approximation shipped instead), exact truncated c-index, and validating the cure model at long horizons.
- **Deep-model depth** — `--deep` wires DeepSurv into `train`; still open: a DeepHit competing-risks variant and architecture/epoch tuning. Optional `[deep]` extra; CUDA is auto-selected.
- **NLP features** — `text_safety.py` is ready (leakage masking + freshness gating) but no description-text feature consumes it yet.
- **Scheduled incremental refresh** — `merge` reconciles deltas, but there is no automated NVD `lastMod`-window pull to keep a live dataset current on a schedule.
- **Project Zero dates** — the live sheet leaves "Date Discovered" blank for the most recent rows (source-side); consider a disclosure-date fallback.
- **WSL RAM cap** — WSL currently sees ~7 GB; set `memory=12GB` in `.wslconfig` (+ `wsl --shutdown`) before running RSF (~10 GB) or concurrent heavy jobs.

## Repository layout

```text
dataset_extraction-20260608T210903Z-3-002/
  dataset_extraction/
    extract/                  Mongo/VRS extraction scripts
    enrich/                   external timestamp and metadata enrichment
    handover/                 student-facing data dictionary
    out/                      generated parquet outputs, ignored by Git
    README.md                 operator notes for rebuilding the handover pack
    temporal_exploit_prediction.md
    run_pipeline.sh
    view_parquet.py
    compare_outputs.py
    requirements.txt
```

Large generated datasets are intentionally ignored by Git. They should be
handled as local artifacts, object-storage artifacts, or separate release files.

## Current source-control policy

Track:

- extraction and enrichment source code
- project documentation
- handover documentation
- dependency manifests
- helper scripts

Do not track:

- parquet outputs
- EPSS history dumps
- local caches
- virtual environments
- logs
- secrets or `.env` files

This keeps the repository useful for collaboration without making normal Git
operations depend on multi-GB binary data.

## Plan for creating the research project

### 1. Stabilize the handover data

- Confirm the nine expected parquet outputs exist.
- Keep generated data out of Git.
- Document the provenance, known biases, and leakage risks for each source.
- Treat the current extraction scripts as reproducibility material, not as the
  main modeling code.

### 2. Build the analysis dataset

- Start from `cve_corpus.parquet` as the per-CVE base table.
- Use `published` as the clock origin.
- Join dated event sources:
  - PoC dates
  - Metasploit dates
  - Nuclei dates
  - CISA KEV dates
  - Google 0-day dates
- Define one or more event labels:
  - time to first public weaponization signal
  - time to PoC
  - time to Metasploit
  - time to Nuclei
  - time to confirmed in-wild signal
- Define a fixed snapshot date and right-censor CVEs with no observed event.

### 3. Avoid temporal leakage

- Use only features knowable at or near publication time for prediction.
- Do not use snapshot-time feed-presence flags as predictors for historical
  events.
- Treat current CVE descriptions carefully because they may contain post-event
  text such as KEV or active-exploitation mentions.
- Use time-based train/test splitting, not random K-fold splitting.

### 4. Run exploratory analysis first

- Plot Kaplan-Meier curves for key event definitions.
- Compare event timing by CVSS severity, CWE class, vendor/product family, and
  ATT&CK tactic where available.
- Quantify censoring and source dominance, especially PoC dominance.
- Identify negative durations and decide whether to drop, floor, or analyze
  them separately.

### 5. Train baseline survival models

- Start with simple, defensible baselines:
  - Kaplan-Meier reference curves
  - Cox proportional hazards
  - random survival forest if available
- Evaluate discrimination and calibration at fixed horizons:
  - 7 days
  - 30 days
  - 90 days
  - 180 days

### 6. Add stronger ML models if time allows

- Test learned text features from CVE descriptions only after addressing
  leakage.
- Compare deep survival models such as DeepSurv or DeepHit against classical
  baselines.
- Explore competing-risk or multi-state modeling for PoC to Metasploit to
  Nuclei to KEV progression.

### 7. Reconcile results against EPSS

- Compare the survival model's multi-horizon predictions with EPSS.
- Identify CVEs where EPSS is high but public weaponization is slow, and where
  EPSS is low but weaponization is fast.
- Frame EPSS as complementary: EPSS predicts exploitation probability in a
  fixed 30-day window, while this project models weaponization timing.

### 8. Produce final research outputs

- A reproducible modeling dataset builder.
- Locked train/test CVE ID splits.
- Survival-analysis notebooks or scripts.
- Evaluation tables and calibration plots.
- A written methodology covering censoring, leakage, event definitions, source
  bias, and limitations.

## Quick start

From the dataset folder:

```bash
cd dataset_extraction-20260608T210903Z-3-002/dataset_extraction
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python view_parquet.py --list
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Modeling quick start

From the repo root (env managed with [uv](https://docs.astral.sh/uv/)):

```bash
uv venv --python 3.12 .venv
uv pip install -p .venv/bin/python -e ".[dev,xgb,boost]"
.venv/bin/temporal-exploit build-dataset --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out --artifact-dir artifacts --snapshot-date 2026-03-14
.venv/bin/python -m pytest
```

Generated artifacts land in `artifacts/` (ignored by Git): `modeling_labels.parquet`,
`publication_features.parquet`, and `manifest.json`. Methodology is documented in
`docs/modeling_methodology.md`.

## Memory: check RAM/VRAM limits before any model work

**Always check free RAM (and VRAM if using `xgb`/`--deep`) before building or
training** — the full dataset is 338k CVEs and the heavier paths page a 16 GB
laptop into the ground if something else is hogging memory:

```powershell
Get-CimInstance Win32_OperatingSystem | Select @{n='FreeRAM_GB';e={[math]::Round($_.FreePhysicalMemory/1MB,2)}}
nvidia-smi --query-gpu=memory.used,memory.total --format=csv
```

Rules of thumb on the full dataset:

- `train --models cox,xgb` — the laptop-friendly default to prefer; XGBoost AFT
  trains on the GPU when present and its survival curves are closed-form, so
  evaluation memory stays flat.
- `train --models cox,rsf` — the RSF is the RAM hog: the fitted forest holds
  per-leaf survival curves (~5 GB resident) plus batched prediction buffers.
  Budget ~10 GB free RAM and close other heavy apps first.
- `build-dataset --epss-path ...` — the 375M-row EPSS history is streamed with
  `iter_batches` + a fixed-size per-CVE numpy reduction (**~0.6 GB peak**; an
  earlier pyarrow `isin` pushdown filter retained ~5.8 GB). The full
  EPSS+landmark build peaks ~1.3 GB process RSS, well within the laptop budget.
- `train --deep` — DeepSurv evaluation is sampled (20k rows) to bound the
  survival-matrix size; training itself runs on the GPU.
- Run one heavy job at a time. Two of the above concurrently is what causes
  the swap-death.

## Main documentation

Read these in order:

1. `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/temporal_exploit_prediction.md`
2. `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/handover/README.md`
3. `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/README.md`

