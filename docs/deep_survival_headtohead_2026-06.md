# Deep-Survival-vs-Cox Head-to-Head at First-Weaponization Scale (the AI artefact)

**Date:** 2026-06-21. **Question (per `temporal_exploit_prediction.md` §"What makes this an AI/ML project"):** deep survival (DeepSurv / DeepHit) head-to-head against Cox PH — *not* "do neural nets beat Cox," but **characterise where they win and lose at this dataset scale**. Run on the large first-weaponization target (the data's strength), not the 396-event in-wild head where everything ties. Locked time-based split (cutoff 2024-01-01), merged build, `[deep]` sidecar (torch 2.12 + cu130, RTX 4060). Reproduce: `train --label-set first_weaponization --models cox,xgb --deep` and `train-competing --deep-hit`. **≥8-round reverse-engineering audit (one round fixed a metric bug, one caught a small-sample caveat).**

## 1. Single-event head-to-head (212,824 train / 101,023 test; 45,527 test events)

| model | discrimination (held-out c-index) | calibration (integrated Brier ↓) |
|---|---|---|
| **XGBoost-AFT** | **0.614 [0.610, 0.619]** (Uno IPCW) — wins | 0.240 |
| Cox PH | 0.562 [0.558, 0.567] (Uno IPCW) | **0.220 — wins** |
| DeepSurv | 0.575 (Antolini time-dependent C) | 0.287 — worst |

**Verdict: DeepSurv (the neural net) wins on neither axis.** Middle on discrimination (below xgb), **worst on calibration** (Brier 0.287 vs Cox 0.220, IPA worst). **XGBoost-AFT wins discrimination; Cox wins calibration.** Textbook tabular-survival outcome — matches Burk et al. 2026 ("no method significantly beats Cox PH on tabular survival") and the broad finding that deep survival rarely wins on tabular data.

**RE caveats on the c-index (a real metric bug was found and fixed):**
- The **full-set** c-index (`ipcw` == `truncated`, with the analytic Noether CI above) is the standard discrimination metric and is what's reported.
- The per-run **bootstrap** CI was computed on an **events-only** subpopulation whenever events > `max_eval` (45,527 > 20,000) — it dropped every event-vs-censored pair, collapsing toward the *event-vs-event* ordering (~0.51) and producing a CI that did not bracket the point estimate. **Fixed** (`bootstrap_cindex_report` now retains a censored subsample; TDD regression test). Use the Noether CI, not the old bootstrap CI.
- The events-only ordering finding stands on its own merits: **among weaponized CVEs, publication features barely rank *which* weaponized first (~0.51)** — consistent with PoC timing being shaped by disclosure logistics + the PoC-date artifact (see `pipeline_characterization_2026-06.md`).
- DeepSurv's `concordance_td` is **Antolini's** time-dependent C, a *different estimator* than cox/xgb's Uno IPCW — same ballpark, not a strict tie-break. The integrated Brier IS a comparable estimand across all three.

## 2. Competing-risks head-to-head: cause-specific Cox vs DeepHit

**Cause-specific Cox (the working competing-risks model)** — held-out Harrell C per cause, RE-re-derived independently:

| cause | **test** events | c-index | note |
|---|---|---|---|
| poc | 45,104 | 0.563 [0.560, 0.566] | rock-solid; **matches the single-event Cox 0.562** (cross-check) |
| vulncheck_kev | 102 | 0.749 [0.684, 0.798] | well-tested |
| exploitdb | (3,794 train) | 0.728 | EPSS + CWE-119/434/94 driven |
| nuclei | 937 train | 0.702 | |
| metasploit | **36** | 0.889 [0.844, 0.923] | **small test sample — optimistic, not robust** |
| kev | **6** | 0.834 [0.777, 0.910] | **6 test events — unreliable** |
| google_0day | 1 | null | too few to evaluate |

The interpretable per-cause coefficients are a genuine win of the classical model (e.g. metasploit driven by CWE-78/CWE-94 injection weaknesses; exploitdb by EPSS-at-publication). **Caveat (RE-caught):** the strong rare-cause numbers (metasploit, kev) rest on 36 and 6 *test* events — their bootstrap CIs are on those tiny samples; treat as directional, not headline.

**DeepHit (joint neural competing-risks) — collapsed.** Predicted CIF@90 ≈ **3.0e-06** for the dominant `poc` cause where the true Aalen-Johansen CIF is ~**0.19** (5 orders of magnitude too small); per-cause concordance ≈ **0.50** (chance). DeepHit put ~all probability mass on the censored cell and learned nothing — a known failure mode on **extreme imbalance** (52% censored, poc = 84% of events, rare causes ~0.05%) with the standard config. **This is a negative result, not a fair comparison**; a usable DeepHit would need imbalance handling (rebalanced/focal loss) + a representative (not 20k-sampled) eval — future work.

## 3. Overall verdict — where do deep models win and lose?

**At this dataset scale, deep survival does not win on either head:**
- **DeepSurv** (single-event) is dominated — xgb ranks better, Cox calibrates better, DeepSurv calibrates worst.
- **DeepHit** (competing-risks) collapses on the rare-event imbalance the data is made of.
- The **working tools are classical**: XGBoost-AFT for discrimination, Cox PH for calibration and for the interpretable competing-risks layer.

This is exactly the professor's framing realised ("the point is **not** that neural nets beat Cox… characterise where they win and lose"): the deep models' theoretical strengths (non-PH, learned joint CIFs) don't manifest as a win on this tabular, heavily-censored, PoC-dominated data — and DeepHit's imbalance fragility is itself an informative finding.

## 4. Caveats (required for the viva)
- **PoC-date artifact** (see Phase 1): a common confound across all models — it depresses every absolute number; the *relative* deep-vs-classical ranking is robust to it (all models see the same labels).
- **Informative censoring**: assumed-away by all methods; over-represents niche/unmonitored CVEs in the censored set.
- **Deep models were run with standard configs**; a tuned DeepHit (imbalance-aware) and DeepSurv (architecture search) could narrow the gap — but the literature prior is that they still wouldn't decisively beat Cox/GBM on tabular survival.

## 5. Reverse-engineering audit (≥8 loops)
1. C-index estimand contradiction → resolved (events-only bootstrap bug) + **fixed** with TDD. 2. Cox PH overflow → cosmetic (diagnostics only; c-index uncorrupted). 3. DeepSurv concordance estimator (Antolini vs Uno) → comparability flagged. 4. Integrated Brier → comparable estimand across all three. 5. Naive baselines → models beat the KM null; event rates sane (23%/31%/38%/40%). 6. int8 downcast → cox/xgb risk identical to 0.00e+00, deep float32 input bit-identical (zero quality loss). 7. Cause-specific Cox → independently re-derived; **poc 0.563 == single-event 0.562 cross-check**; small test-event caveat caught. 8. DeepHit collapse → confirmed CIF 3e-6 vs AJ truth 0.19 (not an eval artifact).
