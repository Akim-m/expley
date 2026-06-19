# Design: rolling-origin weaponization backtest (2026-06-19)

> Self-reviewed (autonomous-spec-and-plan). **Main aim, never lost: time to
> public weaponization.** The backtest measures how accurately the model
> predicts that timeline *prospectively*, the way it would be deployed.

## Why (settled in discussion)
A single time-split at 2024-01-01 is the k=1 case of what we want: one arbitrary
cutoff (no stability estimate), train+test censored at the same final snapshot
(the IPCW-degeneracy source), and it scores "happened by snapshot" not "was the
forward timeline right." The better approach is a **rolling-origin walk-forward
backtest with point-in-time (as-of) censoring** — each origin is a prospective
time-split; aggregating gives the distribution + reliability the single split
can't.

## Core invariant — as-of censoring
At origin T the training labels must censor any event dated after T (not yet
observed at T). The label builders already take a `snapshot_date` and do exactly
this — so as-of-T labels = `build_first_weaponization_labels(corpus, events, T)`.
Features are publication-time and origin-invariant for CVEs published before T,
so they're built **once** and reused (cheap + memory-light). Only labels change
per origin.

## `src/temporal_exploit/backtest.py`
- `make_origins(snapshot_date, start, freq="Q", min_followup_days=180) -> list[str]`
  — quarter-start timestamps from `start` up to `snapshot − min_followup` (so the
  last origin still has follow-up to observe outcomes).
- `rolling_origin_backtest(corpus, event_frames, features, snapshot_date, origins,
  model="cox", label_set="first_weaponization", horizons=(7,30,90,180)) -> dict`:
  - final-snapshot labels (full observation) built once for scoring test batches.
  - per origin T (next = following origin, last→snapshot): train = published `< T`
    with as-of-T labels; test = published in `[T, next)` scored with **final**
    outcomes. Fit the model; score via the existing **censoring-free**
    `evaluate_survival` (horizon-AUC + IPA + calibration — the metrics that don't
    rely on the degenerate IPCW weights) + operational metrics.
  - returns `{per_origin: [...], aggregate: {horizon_auc/ipa mean±sd over origins,
    pooled reliability}}`.
- `operational_metrics(risk, test_frame, horizons, top_frac=0.1)` — the
  decision-relevant ones for a *timeline*: **recall@top-N** (of CVEs that actually
  weaponized within h, the fraction flagged in the top decile of predicted risk)
  and **median lead-time** (predicted-vs-actual for flagged weaponizers).

## `src/temporal_exploit/simulate.py` (estimator validation)
`synth_weaponization(n, cure_fraction, ...)` — generate a synthetic corpus +
event frames from a **known** mixture-cure DGP (logistic incidence + log-logistic
latency, feature-driven), with real publication dates so the same backtest runs
on it. Confirms the harness recovers known calibration/discrimination, and a
sweep over cure-fraction/censoring/signal maps where the model breaks — i.e. how
much of in-wild IPA≈0 is the data vs the model.

## Negative controls (tests, non-negotiable)
- **Permutation:** shuffle event dates → backtest horizon-AUC must collapse to
  ~0.5 (proves the harness has no look-ahead leak).
- **As-of leak guard:** a future-only signal must not improve as-of accuracy.

## CLI
`temporal-exploit backtest --artifact-dir … --snapshot-date … [--start …]
[--model cox|xgb|cure] [--label-set first_weaponization|in_wild]` → writes
`backtest_metrics.json` (per-origin + aggregate).

## Out of scope (stay anchored)
No new modeling targets, no new feeds — this is *evaluation* of the existing
time-to-weaponization model. Reuses prepare_modeling_frame / fit_* /
evaluate_survival; the new code is the origin loop, as-of labels, operational
metrics, synthetic generator.

## Memory
Features built once; per-origin frames are subsets; cox/xgb/cure fits are light.
K≈10 origins × one fit ≪ the budget. No EPSS rescan (features prebuilt).

## Self-review
Coverage: as-of censoring ✓, walk-forward ✓, timeline metrics (horizon-AUC +
reliability + recall@N + lead-time) ✓, synthetic validation ✓, negative
controls ✓, anchored on first-weaponization ✓. No placeholders. Types: `origins`
is list[str] throughout; `rolling_origin_backtest`/`operational_metrics`/
`synth_weaponization` signatures consistent.
