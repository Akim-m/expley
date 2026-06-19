# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Environment:** WSL2 Ubuntu (migrated 2026-06-12 — see `docs/superpowers/plans/2026-06-12-wsl-migration.md` for the record and benchmarks). Data lives in the repo: handover parquets under `dataset_extraction-*/dataset_extraction/out/`, the 3.7 GB EPSS history at `epss_history-001.parquet` (repo root). Use **uv** for env/package management (user preference — it's faster). WSL RAM is capped well below the host's 16 GB; check `free -g` before heavy model work.

## What this is

A survival-analysis modeling layer that predicts **when** a published CVE becomes publicly weaponized (time-to-event), built on a pre-extracted multi-source CVE timeline dataset. It complements EPSS (which predicts in-the-wild exploitation probability over a fixed 30-day window) by characterizing the upstream weaponization pipeline: PoC → Metasploit/Nuclei → KEV/0-day.

## Two layers — keep them separate

1. **`dataset_extraction-20260608T210903Z-3-002/dataset_extraction/`** — immutable handover/source material. Extraction (`extract/`, from a VRS MongoDB dump) and enrichment (`enrich/`, git-mining + EPSS/MITRE) scripts that produced nine parquet files under `out/`. Treat as reproducibility material; do not modify to change modeling behavior. The framing doc (`temporal_exploit_prediction.md`) and `handover/README.md` are the authoritative domain references.
2. **`src/temporal_exploit/`** — the modeling package (the code we develop). Reads the handover parquets, never writes to them. Generated outputs go to `artifacts/` (gitignored).

## Commands

Use the repo venv interpreter (`.venv/`), not the system Python. Manage the env with uv:

```bash
# create env + install (editable, with dev deps)
uv venv --python 3.12 .venv
uv pip install -p .venv/bin/python -e ".[dev,xgb,boost]"

# full test suite — the FutureWarning gate is baked into
# pyproject [tool.pytest.ini_options], so plain pytest just works:
.venv/bin/python -m pytest -q

# single test
.venv/bin/python -m pytest tests/test_labels.py::test_name -v

# build the modeling dataset from the handover parquets
.venv/bin/python -m temporal_exploit.cli build-dataset \
  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \
  --artifact-dir artifacts --snapshot-date 2026-03-14 [--cutoff-date 2024-01-01]

# inspect any handover parquet (predicate pushdown — safe on the 375M-row EPSS file)
.venv/bin/python dataset_extraction-20260608T210903Z-3-002/dataset_extraction/view_parquet.py epss_history --schema-only
```

The console script `temporal-exploit` (entry point `temporal_exploit.cli:main`) is available after install.

## Architecture and data flow

`cli.build_dataset_command` is the integration point and shows the pipeline order:

```
load_parquet (loaders) → validate_columns (schema) → build_first_weaponization_labels (labels)
                                                    → build_publication_features (features)
                                                    → write parquets + manifest (artifacts)
                                                    → [optional] make_time_split / write_time_split (splits)
                                                    → feature_provenance().to_csv
```

- **labels.py** — `published` is the per-CVE clock origin. The event is the earliest dated signal across the five sources (`EVENT_SOURCES` in cli.py); CVEs with none are right-censored at `--snapshot-date` (`event_source == "censored"`). Events dated before publication are flagged via `negative_duration_flag` and **preserved, not dropped**.
- **features.py** — publication-time structured metadata only. `build_publication_features` raises on missing required columns (no silent degradation). `feature_provenance()` is the leakage audit trail — one row per feature family with `leakage_status`.
- **splits.py** — time-based split on `published` at a fixed cutoff; writes locked `train/test_cve_ids.txt`. Never random K-fold.
- **baselines.py** — Kaplan-Meier + Cox PH (lifelines). Both reject negative durations; callers must exclude `negative_duration_flag` rows first.
- **evaluate.py** — naive event-rate-by-horizon (7/30/90/180 days) and event-source composition.
- **epss_features.py / landmark.py** — the 375M-row `epss_history` is read by streaming `iter_batches` + numpy membership (`get_indexer`), reduced to one value per CVE (~300 MB RSS). **Do not** add an `isin(cve_ids)` pyarrow pushdown — it retained ~5 GB. The one safe pushdown is by **date**: `_iter_epss_batches` skips row groups outside `[earliest published, snapshot]` (the file is one row group per day), speeding up historical-snapshot builds with no result change.

## Non-negotiable constraints (these are how results stay valid)

- **Leakage safety.** Default features must exclude: `description` text (NVD back-edits it post-event with "actively exploited"/"CISA"/"KEV" phrasing — temporal leakage), snapshot-time presence flags (`vrs_presence`), and snapshot-time EPSS. Only publication-time-knowable values are safe (CVSS, CWE, CPE vendors/products, ATT&CK from the stable MITRE chain, first EPSS reading *after* publication). When adding a feature, add a `feature_provenance()` row and justify its `leakage_status`.
- **Timezone.** All handover date columns are `timestamp[ns, tz=UTC]`. Normalize every date with `utc=True` and use tz-aware snapshots/cutoffs — mixing tz-aware and naive raises on subtraction.
- **Real column names.** The handover schemas use `cvss_v3_base`, `cwe_ids`, `kev_date_added`, `zeroday_date_discovered`, `poc_first_seen`, `metasploit_first_seen`, `nuclei_first_seen` — verify against the actual parquet (`view_parquet.py --schema-only`) before assuming names; wrong names silently produced all-zero features before they were caught.
- **List columns load as `numpy.ndarray`**, not Python lists — `list_len`/`has_list_value` must handle ndarray.

## Critical framing caveat

~97% of observed events are public-PoC dates; KEV (`dateAdded`) and Google 0-day are the only true in-the-wild signals (~664 events combined). Any model trained on first-weaponization labels predicts **time to public exploit tooling**, not in-the-wild exploitation. Don't position it as an EPSS competitor. See `docs/modeling_methodology.md` §9/§11 and `temporal_exploit_prediction.md` §Framing.

## Workflow

- TDD: failing test → minimal implementation → green → commit. Tests use the tiny fixtures in `tests/fixtures/tiny_parquets.py`, which mirror the real schemas (tz-aware UTC, ndarray lists). The end-to-end test round-trips through parquet on disk — keep it as the guard against schema drift.
- `docs/superpowers/plans/` holds implementation plans; `docs/progress.md` is the detailed living tracker.
- When work lands, update **both** `docs/progress.md` (detailed) and the README's **Project status** + **Scope for improvement** sections (high-level) so the next agent sees current state and what's left.
