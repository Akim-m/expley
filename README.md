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

From the repo root:

```bash
python -m pip install -e ".[dev]"
temporal-exploit build-dataset --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out --artifact-dir artifacts --snapshot-date 2026-03-14
pytest
```

Generated artifacts land in `artifacts/` (ignored by Git): `modeling_labels.parquet`,
`publication_features.parquet`, and `manifest.json`. Methodology is documented in
`docs/modeling_methodology.md`.

## Main documentation

Read these in order:

1. `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/temporal_exploit_prediction.md`
2. `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/handover/README.md`
3. `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/README.md`

