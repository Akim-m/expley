# Landmarked post-publication features (research roadmap P2)

**Goal:** Implement the landmark design from `docs/research_improvements_2026-06.md` §Priority 2:
features as-of `published + L` days with the prediction clock restarted at the landmark.
Target pairing is the **in-wild label set** (KEV + Google 0-day), where post-publication
tooling signals (PoC/Metasploit/Nuclei observed by L) are leakage-safe covariates — the
EE-style artifact features the literature says dominate static metadata.

**Why in-wild, not first-weaponization:** survivors at L have, by definition, no
first-weaponization event by L — so tooling-by-landmark features are degenerate zeros
for that target. For in-wild, a PoC existing by day 30 is exactly the kind of
"exploitation pipeline is moving" evidence we want.

**Constraint discovered:** the corpus `reference_count` is snapshot-time (not dated), so
the research doc's "reference counts at landmarks" idea is not implementable from the
handover. Dated signals available: poc_dates (multi-row, with paths), metasploit_dates,
nuclei_dates, kev_events, EPSS daily history.

## Design

New module `src/temporal_exploit/landmark.py`:

- `build_landmark_features(corpus, tooling_frames, landmark_days)` — per CVE and per
  source `{src}` in {poc, metasploit, nuclei}: `{src}_by_landmark` (first-seen ≤
  published+L), `{src}_lag_days` (publication→first-seen days when ≤ L, else -1.0),
  and for multi-row sources `{src}_count_by_landmark`. All values are facts observable
  at the landmark.
- `build_epss_at_landmark(corpus, epss_path, landmark_days, snapshot_date)` — LAST EPSS
  reading in `[published, published+L]` (vs. `build_epss_at_publication`'s FIRST on/after
  published); same streamed batch scan with incremental reduce, `keep="last"`.
- `restart_clock(labels, landmark_days)` — risk set at L: drop rows with
  `duration_days <= L` (event or censoring before/at the landmark; also removes
  negative durations); subtract L from `duration_days` for the rest. Output feeds the
  existing `prepare_modeling_frame`/`time_split_frame`/train flow unchanged.
- `landmark_feature_provenance(landmark_days)` — `leakage_status="landmark_safe"`, notes
  that validity requires the model clock to start at the landmark (use `restart_clock`).

CLI wiring:
- `build-dataset --landmarks 7,30` writes `landmark_features_{L}d.parquet` per L
  (tooling features always; EPSS-at-landmark folded in when `--epss-path` given).
- `train --landmark L` loads that parquet, merges onto publication features, applies
  `restart_clock` before the split. `metrics.json` records `landmark_days`.

## Evaluation

Compare in-wild Cox/xgb c-index: static features vs. static+landmark at L=30,
same cutoff 2024-01-01. Static in-wild baseline run first for comparison.

## Status — DONE (2026-06-12)

- [x] Plan
- [x] TDD: tests on tiny fixtures (boundary at exactly L, survivor filtering, EPSS last-≤-L)
- [x] Module + CLI wiring, suite green (169 tests)
- [x] Real-data run: in-wild L=30 same-risk-set ablation — cox 0.819→0.874 (+5.5 c-index
      points from landmark features), xgb 0.785→0.798. Report: `artifacts/report_inwild_lm30/`.
      Caveat: ~190 test events → wide CIs (audit P0.3); treat the gain as strong but
      provisional until bootstrap CIs land.
- [x] Edge cases from same-day audit fixed: lag sentinel collision (now L+1 fill,
      pre-pub lags preserved), duplicate-cve_id / NaT published guards, negative
      landmark rejection, stale-parquet NaN guard in train, xgb AFT inf-risk clip.
- [x] Docs (progress.md + README + audit doc) and commit
