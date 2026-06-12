# Progress

Living status + roadmap for the temporal-exploit modeling system. Update as work lands.

Last updated: 2026-06-12.

## Recently landed (this initiative)
- **Modeling & training (E):** `modeling.py` — `prepare_modeling_frame` (drops negative/zero durations), `time_split_frame`, leakage-safe numeric feature matrix, `fit_cox` (lifelines, penalized) + `fit_rsf` (scikit-survival RandomSurvivalForest, sub-sampled), and `evaluate_survival` with IPCW concordance + (integrated) Brier, horizon support-clipping, and tau fallback. `train` CLI subcommand fits both models on a time split and writes `metrics.json` (Cox, RSF, KM reference, naive event-rate). scikit-survival added as a dependency.
- Project `CLAUDE.md`; this `progress.md` roadmap.
- Per-signal labels + competing-risks labels (workstream A1/A2) — decouples PoC from in-wild signals.
- ATT&CK-chain features (B1) and EPSS-at-publication features (B2), both leakage-safe with provenance.
- **`vrs_presence` wired (B4)** — the last unused handover source — as a separate, leakage-flagged `presence_snapshot.parquet` (never merged into the safe features). **All nine handover sources are now used in the dataset.**
- **Fetch layer (C):** `Connector` interface + live connectors for **CISA KEV, EPSS-daily, NVD 2.0** + a `temporal-exploit fetch` CLI subcommand. Live KEV fetch verified against CISA — pulled 1,618 entries dated to yesterday (handover had 1,542).
- CLI `build-dataset` writes `per_signal_labels.parquet`, `competing_risks_labels.parquet`, `presence_snapshot.parquet`; optionally enriches features via `--technique-chain` / `--epss-path`; manifest records which sources were wired.
- Full real build (all nine sources) validated: corpus 338,015; presence 9,009; ATT&CK coverage 25.1%; presence flags confirmed OUT of the safe features; provenance carries both `publication_time_safe` and `snapshot_leakage`.
- Gap fixes from review: empty-frame concat FutureWarning eliminated (labels + nvd); EPSS earliest-row NaN-safe; NVD paging hardened against short/zero pages; NVD `cisa_exploit_added` + real `apiKey` header.
- 82 tests passing (`-W error::FutureWarning`).

## Done

### Modeling core (merged to `master`)
- **Package + tooling** — `pyproject.toml`, `src/temporal_exploit/` package, console script, pytest config.
- **Loaders + schema** — `load_parquet`, `load_required_parquets`, `validate_columns` with real handover column names. Fails loudly on missing columns.
- **Labels** — `build_first_weaponization_labels`: earliest event across the five dated sources, UTC-normalized, right-censoring at snapshot, `negative_duration_flag` (preserved not dropped).
- **Features** — `build_publication_features`: leakage-safe publication-time metadata (CVSS + missing indicator, severity one-hot, CWE/vendor/product counts, year). `feature_provenance()` audit trail. ndarray-safe list handling.
- **Splits** — time-based on `published`, locked `train/test_cve_ids.txt` + metadata. UTF-8.
- **Baselines** — Kaplan-Meier + Cox PH (lifelines), both reject negative durations.
- **Evaluation** — `event_rate_by_horizon` (7/30/90/180), `event_source_counts`.
- **CLI** — `build-dataset` builds labels + features + manifest, optional locked splits, always writes `feature_provenance.csv`.
- **Docs** — `docs/modeling_methodology.md` (verified accurate), README quick start, project `CLAUDE.md`.
- **Quality** — 34 tests; every phase passed two-stage review; validation gate run on the real 338k-row dataset (CVSS mean 4.98, non-zero list counts, PoC-dominant events).

### Critical defects fixed (found in first review)
- tz-aware date crash in label builder.
- wrong schema column names (`dateAdded`→`kev_date_added`, `date_discovered`→`zeroday_date_discovered`).
- wrong feature columns (`cvss_v3_base_score`→`cvss_v3_base`, `weaknesses`→`cwe_ids`) with silent zero-degradation.
- `list_len` returning 0 for numpy arrays.

## Data sources — wiring status

| Source | Parquet | Used today | Target |
|---|---|---|---|
| CVE corpus (NVD/VulnCheck) | `cve_corpus` | ✅ features + clock origin | keep |
| PoC (Trickest + Nomi-sec) | `poc_dates` | ✅ event source | split out as its own competing risk |
| Metasploit | `metasploit_dates` | ✅ event source | per-signal target |
| Nuclei | `nuclei_dates` | ✅ event source | per-signal target |
| CISA KEV | `kev_events` | ✅ event source | per-signal target + secondary in-wild label |
| Google 0-day | `google_0day` | ✅ event source | per-signal target + secondary in-wild label |
| EPSS history | `epss_history` | ❌ unused | EPSS-at-publication feature (leakage-safe) + reconciliation |
| ATT&CK chain | `technique_cwe_chain` | ❌ unused | tactic-level one-hot features + `has_attack_chain_mapping` |
| VRS presence | `vrs_presence` | ❌ unused | descriptive / censored-rows-only (snapshot leakage) |

## In progress / next (this initiative)

Four workstreams from the directive "more public datasets, fetch till now, deal with PoC timing, wire every source." Ordered by value/risk.

### A. Deal with PoC timing (highest priority — it's the core framing problem)
PoC is 97% of events, so a single first-weaponization model mostly learns PoC/disclosure logistics.
- **A1. ✅ Done.** `build_per_signal_labels` — per-source `{src}_event_date/_observed/_duration_days/_negative_duration_flag`, so each signal is modeled independently. Wired into the CLI (`per_signal_labels.parquet`). Real build: PoC observed 164,761; KEV 1,542; each signal now separable.
- **A2. ✅ Done.** `build_competing_risks_labels` — long-format `(cve_id, published, duration_days, event_cause, cause_code, event_observed)` for lifelines cause-specific hazards / pycox DeepHit. Deterministic `cause_code` (0==censored). Wired into the CLI (`competing_risks_labels.parquet`).
- **A3. ✅ Done.** `build_in_wild_labels` — secondary survival target using only KEV + Google-0day (PoC excluded). Wired into the CLI (`in_wild_labels.parquet`, manifest `in_wild_observed`). Real build: 1,543 confirmed in-wild events (KEV 1,410 + 0-day 133) vs 336,472 censored.
- **A4. ✅ Done.** `evaluate.cascade_order_stats` — for adjacent stages (PoC→MSF→Nuclei→KEV), % where stage a precedes stage b among CVEs observed in both, to motivate multi-state vs independent modeling.

### B. Wire every remaining source
- **B1. ✅ Done.** ATT&CK-chain features from `technique_cwe_chain` (`attack_features.py`): `has_attack_chain_mapping`, `attack_technique_count`, top-k parent-technique one-hot (parent = technique id with sub-technique stripped — lower dimensionality, no external tactic data needed). Wired into the CLI via `--technique-chain`. Real build: coverage 25.1% (matches MITRE-chain coverage). *Tactic-level aggregation deferred — needs the external ATT&CK technique→tactic map (a fetch, workstream D).*
- **B2. ✅ Done.** EPSS-at-publication (`epss_features.py`): first EPSS reading on/after each CVE's `published` (leakage-safe), `epss_at_publication_missing` for pre-2021-04-14/absent CVEs. pyarrow predicate pushdown over the 375M-row file. Wired into the CLI via `--epss-path`. Verified against the real 3.9GB file (sane values, ~9s for a small corpus). *Full-corpus EPSS is a heavier run; treat as an opt-in enrichment.*
- **B3. ✅ Done.** `evaluate.epss_reconciliation` — 2×2 of high-EPSS-at-publication × fast-weaponized (drops EPSS-missing CVEs), for RQ4 (where EPSS over/under-estimates observed weaponization).
- **B4. ✅ Done.** `vrs_presence` wired as the separate leakage-flagged `presence_snapshot.parquet` (see "Recently landed").

### C. Fetch data "till now" (live/incremental)
`src/temporal_exploit/fetch/` package: pluggable connectors that refresh each source to the current date and write to a separate `data/live/` dir (gitignored) without mutating the handover parquets, recording fetch provenance in `fetch_manifest.json`.
- **C1. ✅ Done.** `Connector` ABC + `save` + `write_fetch_manifest`. Network isolated in module-level `_fetch_*` fns (mocked in tests).
- **C2. ✅ Done.** CISA KEV live (`fetch/kev.py`). Verified live (1,618 rows to yesterday).
- **C3. ✅ Done.** FIRST.org EPSS daily CSV.gz (`fetch/epss.py`) → epss_history schema for a given day.
- **C4. ✅ Done.** NVD 2.0 API (`fetch/nvd.py`) → full cve_corpus schema, paged, apiKey header, hardened termination.
- **C5. ◐ Partial.** Git-mined sources, re-implemented in-package (not importing the immutable `enrich/` tree). Shared `fetch/gitmine.py` primitives: `shallow_clone` (`--no-checkout`, optional `with_blobs`), `first_add_dates` walk, `earliest_by_cve`, `file_at_head`, `earliest_introduction` (`-G` pickaxe). Connectors: **Nuclei** + **PoC** (Trickest+Nomi-sec) via path-based first-add; **Metasploit** (`fetch/metasploit.py`) via manifest + `git log -G` introduction date. **Project Zero** (`fetch/zeroday.py`) fetches Google's "0day In the Wild" sheet CSV export → `google_0day` schema. All wired into `fetch --source {nuclei,poc,metasploit,zeroday} [--repo|--url]`. Live-verified end-to-end: KEV/EPSS/NVD/Nuclei/PoC/Project Zero all fetch current-to-today (Nuclei 4,192 CVEs/13.7s; Trickest 159,902/19.3s; Nomi-sec 27,847/8.7s; Project Zero 404 rows/1.0s). Metasploit connector is mock-tested; its full live mine (blob clone + ~1hr `-G` across ~3,500 pairs) is opt-in and not run inline. **All README sources now have live connectors — section C complete.**
- **C5 note.** `merge.py` also reconciles a refreshed `google_0day` (full-snapshot, live wins), so the Project Zero connector flows through `merge` like KEV/EPSS/NVD.
- **C6. ✅ Done.** `merge.py` + `merge` CLI: `merge_live(handover_dir, live_dir, out_dir)` reconciles live deltas onto the handover parquets into a unified dir the build can consume — KEV full-snapshot (earliest `kev_date_added`), NVD corpus by newest `last_modified`, EPSS day-append by `(cve_id, date)`. Unmerged sources file-copy through (the 375M-row EPSS handover is never loaded unless it is the source being merged). Records per-source row deltas in `merge_manifest.json`.

### E. Modeling & training
- **E1. ✅ Done.** `modeling.py` + `train` CLI: Cox PH and RandomSurvivalForest on a time split, IPCW c-index and (integrated) Brier with horizon support-clipping, `metrics.json` report.
- **E2. ✅ Done.** `train --label-set {first_weaponization,in_wild}` selects the labels parquet; `metrics.json` records `label_set`. In-wild target (`in_wild_labels.parquet`, KEV+0-day only) is now trainable — the project's stated meaningful target.

### D. More publicly available datasets — DESCOPED
Per scope guidance (2026-06-12): stay within the README's defined sources. New external feeds (OSV, GHSA, ExploitDB, VulnCheck API) are **out of the project's main scope** and parked unless explicitly requested. The "more public data" need is met by live-refreshing the README's own sources (workstream C).

## Scope for improvement (backlog / quality)
- ✅ Artifact content hashes (`artifact_sha256`, SHA-256 per parquet/csv) in `manifest.json` for reproducibility.
- ✅ Cox proportional-hazards diagnostics — `modeling.cox_ph_assumptions` (per-covariate `proportional_hazard_test`, `violates` flag); folded into `train` `metrics.json` as `cox_ph_assumptions`.
- Event-source dominance warning emitted at build time when one source >X% of events.
- ✅ Calibration / reliability at 7/30/90/180 days — `modeling.calibration_table` (censoring-aware Kaplan-Meier observed rate per predicted-risk bin) + `plot_calibration`; `train` writes `calibration_{cox,rsf}.png` and folds the per-horizon tables into `metrics.json`. Constant-prediction (pre-first-event) bins collapse safely. (Brier already in `evaluate_survival`.)
- ✅ Description-text leakage mitigation (`text_safety.py`): `mask_leakage_terms` (redacts "actively exploited"/KEV/CISA/etc.) + `description_is_fresh` / `build_safe_descriptions` (blanks descriptions back-edited > ε days after `published`). Groundwork utility — not wired into the build until an NLP feature consumes it.
- ✅ Deep survival model (DeepSurv via pycox) — `deep.py` (`fit_deepsurv` + `evaluate_deepsurv` with time-dependent concordance + integrated Brier). Auto-selects CUDA when available (moves the net to GPU). Kept optional: lazy torch imports, `deep` extra (`pip install -e ".[deep]"`), `importorskip`-gated tests so core/CI stay torch-free. Core suite stays green (deep test skips without torch). Verified end-to-end on GPU in an isolated torch(cu128, py3.14)+pycox venv — trained on the RTX 4060, evaluated with time-dependent concordance + integrated Brier. Needed a `scipy.integrate.simps`→`simpson` compat shim (pycox<=0.3 vs scipy>=1.14).
- ✅ CI workflow (`.github/workflows/ci.yml`: ruff + pytest on push/PR, py3.12) and pre-commit hooks (`.pre-commit-config.yaml`: hygiene hooks + ruff). Ruff lint is pyflakes-only (`F`) — real defects, no reformatting churn.
- ✅ Pytest workaround baked into `pyproject` `addopts` (`--basetemp=.pytmp -p no:cacheprovider`) + `filterwarnings=["error::FutureWarning"]`, so plain `pytest` runs with the gate on.

## Conventions
- TDD, one focused commit per change, two-stage review for non-trivial work.
- Leakage discipline and tz/column-name rules per `CLAUDE.md`.
- Generated data (`artifacts/`, `data/live/`) stays gitignored.
