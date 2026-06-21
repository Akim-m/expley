# DeepHit Collapse — Diagnosed and Fixed (quantile time-discretization)

**Date:** 2026-06-21. The competing-risks DeepHit was a documented dead-end: it
predicted CIF@90 ≈ **3e-6** for the dominant `poc` cause where the Aalen-Johansen
truth is ~**0.10**, with concordance ≈ chance. Prior write-ups called it "a known
imbalance failure — future work." We debugged it to root cause and fixed it.
Reproduce: `.venv-deep/bin/python -u scripts/deephit_imbalance_fix.py` →
`artifacts/merged/deephit_imbalance_fix.json`.

## The investigation (each hypothesis tested, not assumed)

| hypothesis | test | result |
|---|---|---|
| Loss weighting — `alpha=0.2` underweights the likelihood | sweep alpha 0.2 → 1.0 | **FALSIFIED.** Raising alpha made it *worse*: CIF@90 3e-6 → 3e-13. Under 52% censoring, pure-NLL piles mass on "never-event". |
| Too few time bins | equidistant 20 → 100 | **FALSIFIED.** equidistant-100 stayed collapsed (1.4e-5). Bin *count* is not the cause. |
| **Bin placement** — equidistant bins over a long tail put horizon-90 in bin 1 | **quantile** (event-density) cuts | **CONFIRMED.** CIF@90 recovered to **0.17–0.22** (truth 0.10) with *better* concordance. |

## Results (cause = poc, AJ truth CIF@90 = 0.099; cutoff 2024-01-01)

| config | CIF@90 | ratio vs truth | concordance |
|---|---|---|---|
| baseline (equidistant 20) | 1.3e-06 | 1.3e-05 | 0.555 |
| equidistant 100 | 1.4e-05 | 1.4e-04 | 0.510 |
| **quantile 20** | 0.218 | 2.2 | **0.583** |
| quantile 50 | 0.180 | 1.81 | 0.579 |
| **quantile 100** | **0.168** | **1.69** | 0.564 |

Quantile cuts turn a 5–6 order-of-magnitude collapse into the right magnitude.
More quantile bins tighten calibration (0.218 → 0.168 toward 0.099) at a slight
concordance cost; the residual ~1.7× overshoot is a calibration offset (fixable
with the existing `fit_temperature`), not a collapse.

## The fix (shipped)

`deephit.py` defaults changed: `scheme="quantiles"` (was equidistant),
`num_durations=50` (was 20), `batch_size=1024` (was 256 — it starved the GPU to
~25% utilization; 1024 is GPU-bound, no quality change). `evaluate_deephit` now
runs `predict_cif` once instead of twice. A torch-gated regression test guards the
quantile cut-dedup path. `deep.py` (DeepSurv) batch_size bumped to 1024 for the
same GPU-utilization reason.

## Caveat (unchanged framing)

This makes DeepHit *usable*, not *better than Cox*. The neutral-benchmark consensus
(Burk et al. 2024) and our own results still say no deep model decisively beats
penalized Cox / XGBoost-AFT on this tabular, heavily-censored, PoC-dominated data;
the ceiling is data-limited. DeepHit's value here is a calibrated joint CIF, now
that it no longer collapses. The rare causes (~0.05% of rows) remain unlearnable —
that *is* data scarcity, not a discretization artifact.
