# Chapter 5 writing scaffold — Baselines & discrimination

*2026-07-04. Writing scaffold (plan + verified numbers), not prose. Sources:
`docs/deep_survival_headtohead_2026-06.md`, `docs/calibration_by_horizon_2026-06.md`,
`src/temporal_exploit/baselines.py`, `docs/inwild_epss_parity_2026-06.md`. Re-read before final.*

**Chapter thesis:** classical survival baselines — Kaplan–Meier, Cox PH, RSF, and xgb-AFT — provide
an interpretable, calibrated, leakage-free foundation; xgb-AFT is the discrimination workhorse and
Cox the calibration/interpretability anchor. These set the bar Chapter 6's deep models must clear
(and do not).

### 5.1 Kaplan–Meier — the descriptive layer
- Overall and stratified survival curves (by severity / event source). Establishes the shape of the
  weaponisation-timing distribution and the censoring reality (most CVEs never reach a public PoC).
- Note: KM/Cox reject negative durations → callers exclude `negative_duration_flag` rows first.

### 5.2 Cox PH — interpretable hazards
- The interpretable baseline: which publication-time covariates accelerate weaponisation (CVSS, CWE
  classes, CPE breadth, ATT&CK mappings, EPSS-at-publication when included). Report hazard ratios.
- In-wild config: penalized **Cox + EPSS features is the in-wild model** (AUC@90 ≈ 0.82,
  recall@top-decile ≈ 0.51). Cross-check: competing-risks cause-specific Cox for PoC matches
  single-event Cox (0.562/0.563) — internal consistency.

### 5.3 RSF — non-linear tree baseline
- Random Survival Forest: non-linear, no PH assumption. Engineering note (a real constraint to
  report): RSF evaluation materialised a large (n_test × n_event_times) matrix → batched prediction +
  `min_samples_leaf=15` (fully-grown trees overfit censored data and balloon per-leaf arrays).

### 5.4 xgb-AFT — the discrimination workhorse
- XGBoost accelerated-failure-time survival; trains on GPU; closed-form survival curves keep
  evaluation memory flat. **Discrimination winner:** single-event xgb-AFT **0.614** > Cox 0.562;
  in-wild ranking beats EPSS by **+0.100 AUC@30** (Ch7). The measurement-bug caveat (never wrap a
  calibrated EPSS score in an AFT fit — collapses to ~chance) belongs in Ch7; cross-reference it.

### 5.5 Evaluation protocol & the three lenses
- **Discrimination** (time-dependent C-index), **calibration** (most important — integrated Brier /
  calibration-by-horizon; a confident-but-wrong score is dangerous), **accuracy** (Brier). Evaluated
  by the rolling-origin (walk-forward) backtest, never random K-fold.
- Calibration-by-horizon result: report 7/30/90/180 reliability; Cox best-calibrated (integrated
  Brier 0.220). IPA ≈ 0 on the in-wild task is the rare-event reality, not a bug.

### 5.6 Why baselines are the right foundation
- Leakage-safe (publication-time features only), interpretable (Cox HRs), calibrated (Cox), and a
  built-in CPU fallback (plan slide 11) — a complete defensible project even without GPU/deep models.

**Figures:** `fig_two_heads.png`, `fig_operating_points.png`. **Tables:** per-model C-index +
integrated Brier; Cox hazard ratios for the top covariates.
