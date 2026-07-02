# Whole-pipeline improvement design — accuracy, memory, speed (2026-07-03)

## Goal

Improve the temporal-exploit pipeline on three axes — accuracy, memory
management, speed — under the standing constraints, with every claim measured
against recorded baselines. Companion running record:
`docs/improvement_log_2026-07-02.md`.

## Hard constraints

- **Memory gates:** ≤6 GB peak RSS per process (red line), ≤7 GB VRAM.
  Every run measured with `/usr/bin/time -v`.
- **No EPSS data in the model** (user directive 2026-07-02): EPSS is the
  baseline under test; it appears only as the raw-score baseline arm.
  Score-level fusion rejected under the same directive.
- **Leakage doctrine unchanged:** publication-time-knowable features only;
  every new feature gets a `feature_provenance()` row.
- **Accuracy claims** go through the 15-origin rolling backtest with paired
  deltas; never a single split.
- **Numeric refactors** must reproduce prior output (bit-identical where
  feasible) before they count.
- **Do-not-touch list:** the 13 verified optimizations in
  `docs/progress.md` (EPSS streaming rewrite, fused scan, date pushdown,
  earliest-event hoist, vectorized KM/NLL/Breslow, int8 downcast, caps and
  batching) are not re-done.

## Baselines (measured 2026-07-02/03)

| Path | Wall | Peak RSS |
|---|---|---|
| build (fast path) | 21.3 s | 858 MB |
| build + EPSS stream | 4 m 13 s | 1.21 GB |
| 15-origin in-wild xgb backtest (CUDA) | 38.5 s | 1.03 GB |
| test suite (334 pass / 4 skip) | 1 m 47 s | 613 MB |

## Approaches considered

- **A. Measured portfolio (chosen):** speed/mechanical work first (makes every
  later experiment cheaper), then re-metric the headline, then modeling levers,
  then the label connector. Each step gated by baselines + RE loops.
- **B. Labels-first:** attack the binding constraint (label count)
  immediately via Vulnrichment. Rejected as *first* step: leaves the
  iteration loop slow while doing the most uncertain work, and label accrual
  doesn't block the mechanical wins.
- **C. Speed-only bundle:** safest, but ignores the accuracy half of the ask.

## Workstreams (in execution order)

### S1 — Persist the fused EPSS landmark bundle *(speed, IO)*
Build writes `landmark_features_{L}d.parquet` once; the 5+ analysis scripts
read it instead of re-streaming the 375M-row file (~4 min each).
**Accept:** cached output byte-identical to streamed; scripts fall back to
streaming when no bundle exists.

### S2 — Hoist the feature→label merge out of the backtest per-origin loop *(speed)*
Two full ~360k-row merges per origin × 15 origins → merge once, boolean-mask
per origin. **Accept:** identical backtest report on the full 15-origin run;
measured wall-clock drop.

### S3 — Vectorize feature builders; parse the CVSS vector once *(speed, one-time build)*
`features.py` + `incentive_features.py` parse the same vector string twice and
run ~30 Python `.map(lambda)` passes over 360k rows; replace with one
vectorized parse + `get_dummies`/`explode`. **Accept:** bit-identical
`publication_features.parquet` (hash compare).

### S4 — XGB early stopping with a usable validation split + parallel hill-climb *(speed + accuracy)*
The tail validation split is documented to underfit (stops at iter 57,
c-index 0.607→0.537): tail-of-train is censoring-dominated. Use a random
stratified split *within* train (temporally safe: all train rows predate the
origin; validation only selects the boosting-round count). Then enable early
stopping in backtest/hill-climb paths. Parallelize hill-climb candidate
evaluations with a process pool; workers = min(4, cores) sized from the
measured 1.03 GB/backtest so total stays under 6 GB.
**Accept:** paired-delta metrics not worse; hill-climb selection path
unchanged on a fixture; measured speedup; peak RSS under gate.

### A1 — Re-metric the headline *(accuracy reporting; survey's highest value-per-hour)*
Add the field-standard idiom: coverage/efficiency (effort) curves, recall@K,
bootstrap CIs for PR-AUC (Boyd 2013); aggregate the per-origin IPCW c-index
that is currently computed but never reported; stamp the EPSS version
(v3/v4 history; v5 shipped 2026-06-15) in artifacts and README claims.
**Accept:** parity artifact + README carry the new metrics with CIs; the
"PR-AUC tied" claim restated with its noise band.

### A2 — LambdaRank top-push A/B *(accuracy, top-of-list)*
Single-group `rank:ndcg` XGBoost on binary 30d-horizon labels, structural
features only, judged on recall@top-K/coverage curves over the 15 origins vs
the AFT risk ranking. Known: will not move full-curve PR-AUC; targets the
top-K deliverable. **Accept:** paired deltas on recall@{0.1,0.5,1}% with CIs;
adopted only if it wins.

### A3 — Multi-seed + bounded hyperparameter search *(accuracy honesty + variance)*
5-seed averaging (currently seed=0 everywhere) to measure seed-variance of the
+0.100 headline; bounded random search (~20 configs) tuned on the first 8
origins only, confirmed on the last 7 to avoid backtest overfitting.
**Accept:** seed-variance reported; any adopted config wins on the held-out
origins, not just the tuning ones.

### L1 — Vulnrichment SSVC label connector *(accuracy; the only lever that moves PR-AUC)*
Mine cisagov/vulnrichment git history (SSVC `Exploitation ∈ {none,poc,active}`,
~10.9k commits since mid-2024) for timestamped `active` transitions → new
in-wild label source with backfill, GreyNoise-connector pattern. SSVC
Exploitation is a **label, never a feature**; `Automatable` is the one
defensible feature (separate provenance row, optional). Re-run
label-completeness after merge. **Accept:** connector tested against repo
fixtures; event-count delta and backtest impact reported honestly.

### Deferred / stretch (logged, not scheduled)
Discrete-time classification head (evidence says parity); archived-description
tags via cvelistV5/NVD-feed history (medium plumbing, low ceiling); NIST LEV
baseline comparison (citable, an afternoon); beta calibration + conformal risk
control (product features, no ranking change); float32/category dtype pass
(only if a measured win shows up — current RSS is 10–20% of gate).

### Rejected (evidence- or directive-based)
EPSS-in-training in any form (directive); focal/LDAM losses; SMOTE/resampling;
deep-survival/TabPFN/LLM-embedding/GNN swaps; polars/DuckDB migration;
XGB external memory; isotonic calibration at this positive count; faster Cox
solvers outside CV loops; `isin` pyarrow pushdown (known 5 GB balloon).

## Testing & verification

TDD per repo convention (tiny fixtures mirror real schemas). Refactors verified
by hash/byte comparison against pre-change outputs; behavioral changes verified
by paired-delta backtests. After each workstream: RE loops per standing rule
(≤2 subagents × 3–5 loops), improvement-log entry with before/after numbers,
progress.md + README sync when the workstream lands.
