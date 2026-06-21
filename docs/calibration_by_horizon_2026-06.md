# Calibration at Concrete Horizons (7/30/90/180 days)

**Date:** 2026-06-21. Cohort `published>=2021-01-01`, 70/30 time split at `2025-02-26` (train n=124492, test n=54388). Reproduce: `scripts/calibration_by_horizon.py` → `artifacts/merged/calibration_by_horizon.json`.

Reliability is censoring-aware (KM-within-bin); Brier is IPCW (sksurv). Slope ~1 + intercept ~0 = well-calibrated; slope <1 = over-confident. CIs are 1000-resample subject bootstraps.

## COX — c-index(IPCW) 0.584, integrated Brier 0.17027031920705796

| horizon | Brier | slope [95% CI] | intercept [95% CI] | events |
|---|---|---|---|---|
| 7d | 0.157 | 0.645 [0.61, 0.68] | 0.062 [0.054, 0.071] | 17843 |
| 30d | 0.182 | 0.651 [0.62, 0.68] | 0.072 [0.063, 0.082] | 17843 |
| 90d | 0.178 | 0.598 [0.57, 0.62] | 0.082 [0.073, 0.093] | 17843 |
| 180d | 0.15 | 0.541 [0.52, 0.56] | 0.093 [0.083, 0.105] | 17843 |

## XGB — c-index(IPCW) 0.585, integrated Brier 0.24069328266152307

| horizon | Brier | slope [95% CI] | intercept [95% CI] | events |
|---|---|---|---|---|
| 7d | 0.199 | 0.123 [0.1, 0.15] | 0.188 [0.184, 0.192] | 17843 |
| 30d | 0.25 | 0.172 [0.16, 0.18] | 0.212 [0.207, 0.217] | 17843 |
| 90d | 0.262 | 0.23 [0.22, 0.24] | 0.196 [0.189, 0.203] | 17843 |
| 180d | 0.208 | 0.257 [0.24, 0.27] | 0.166 [0.157, 0.174] | 17843 |

## Interpretation (what the numbers say, RE-verified)

**Equal discrimination, very unequal calibration.** Cox and XGB-AFT rank almost
identically (c-index 0.584 vs 0.585), but their *probabilities* diverge sharply:

- **Cox is the better-calibrated model** at every horizon — slope ~0.54–0.65 and
  the lowest Brier/IBS (0.170 vs 0.241). If you need an absolute probability
  (decision-curve thresholds, risk budgets), use Cox, not XGB-AFT.
- **XGB-AFT is badly over-confident** — slope ~0.12–0.26: its normal-AFT survival
  curves push predictions toward 0 and 1 (only ~56% of CIF@30 land in [0.1, 0.9]
  vs ~89% for Cox), so the reliability line is nearly flat. The closed-form
  survival was verified correct (max error 6e-17) — this is a real property of the
  fitted model, not a `survival_at` bug. XGB-AFT is a discrimination/ranking tool
  here, and its probabilities should be temperature-recalibrated
  (`calibration.fit_temperature`) before being read as probabilities.

**Honest caveat — "calibrated" is relative.** Even Cox over-predicts: its
calibration-in-the-large ratio (mean predicted CIF ÷ KM-observed) is 1.13× at 30d
rising to 1.36× at 180d, and its slope drifts further below 1 as the horizon grows
(0.65 → 0.54). So the deployable reading is "Cox is *much better* than XGB and
usable at short horizons, but biased high at long horizons" — not "Cox is perfectly
calibrated." The slope <1 / intercept >0 pattern is classic shrinkage; a
one-parameter temperature recalibration narrows it without touching the ranking.

**RE provenance.** Estimator math checked against an independent weighted regression
(machine precision), censoring-awareness confirmed (KM-within-bin ≠ naive under
heavy censoring), bootstrap deterministic per seed with CIs bracketing the point
estimate, and the Cox>XGB calibration gap reproduced three independent ways
(population over-prediction, extreme CIF histogram, bin-level pred≫observed).
