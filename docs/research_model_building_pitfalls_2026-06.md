# Building a model right — and the mistakes humans and AI make

**Date:** 2026-06-20 · **Method:** deep-research workflow (6 angles → 18 primary sources) +
a **paced re-verification pass** (adversarial verifiers in batches of 5, because the original
run's verification phase was wiped out by API rate-limiting — every claim showed "0-0 abstain",
which is *not* a refutation). Confidence labels:

- **[VERIFIED]** — re-checked against the source by an adversarial verifier, supported.
- **[CORRECTED]** — partly wrong as first stated; the fixed version is given.
- **[REFUTED]** — the cited source does **not** support it (kept only as a caution).
- **[PRIMARY]** — from a primary source but exact figure not independently re-confirmed.

Scoped to our regime: **rare positive events, strict temporal order, ~400 effective
in-wild events, calibrated probabilities required.** Tie-ins to our codebase
(`src/temporal_exploit/`) are flagged ✅ already-doing / ⚠️ gap / ✏️ worth adding.

---

## 1. The correct end-to-end workflow (baseline-first, leakage-safe)

1. **Frame the target before touching a model.** Define the event, the clock origin, the
   prediction horizon, and the censoring rule *first*. ✅ We do this explicitly in `labels.py`
   (publication clock origin, right-censoring at snapshot).
2. **Lock a temporal hold-out immediately**, before any EDA or feature work, so you can't
   tune against it. ✅ `splits.py` writes locked train/test CVE-ID lists.
3. **Establish a dumb baseline** (majority class, CVSS threshold, naive event-rate-by-horizon)
   and never report a fancy model without it. ✅ `evaluate.event_rate_by_horizon` +
   `baselines.fit_kaplan_meier`. The literature is emphatic that the headline number is
   meaningless without the baseline next to it.
4. **All preprocessing fit *inside* the training fold** (scalers, encoders, imputers,
   resampling) — never on train+test together. ⚠️ Audit our feature builders for any global
   `.fit()` before the split (see §3).
5. **Right cross-validation for time-ordered data**: forward-chaining / rolling-origin, or
   purged+embargoed CV — *never* plain shuffled k-fold. ✅ `backtest.rolling_origin_backtest`.
6. **Tune hyperparameters without leakage** — nested CV or a separate validation slice; the
   test set is touched once, at the end.
7. **Pick metrics that survive imbalance** (PR-AUC, Brier, calibration, decision-curve / net
   benefit) — not accuracy or raw ROC-AUC alone (§2). ✅ we use C-index/IPA/Brier; ✏️ add
   PR-AUC + reliability curves on the in-wild head.
8. **Calibrate, then verify calibration** on held-out data (reliability diagram + Brier).
   ✅ `calibration.py` (isotonic/temperature) + `modeling.calibration_table`.
9. **Report honestly**: confidence intervals (bootstrap), ablations, and what was *not*
   improved. ✅ `modeling.bootstrap_cindex_report` (paired Δ vs Cox).

---

## 2. Metric choice under rare events / imbalance — what the evidence says

- **[CORRECTED]** *Which metrics break under rare events.* Accuracy, Brier, PPV/NPV, F1, F0.5
  **depend on the event rate at a fixed sample size** (worse at lower rates) — but, crucially,
  **their bias converges to zero as the effective sample size (event count) grows, regardless
  of rate.** So they're not "always unreliable when positives are rare" (my first phrasing);
  they're unreliable *when events are few*. (Minus et al., *J Clin Epidemiol* 2025,
  [PMC12667734](https://pmc.ncbi.nlm.nih.gov/articles/PMC12667734/).) → For us the binding
  constraint is the **~400 event count**, not the rate per se.
- **[VERIFIED]** **AUC's reliability is driven by event *count*, not rate** — near-zero bias
  once ≈1000 events are present. With ~400 in-wild events we are **below that threshold**, so
  report AUC with wide bootstrap CIs and lean on count-robust summaries. (same source)
- **[VERIFIED]** **Report multiple metrics with variability estimates**, never a single
  headline. (same source)
- **[VERIFIED]** **ROC-AUC / c-statistic is a rank-order statistic, insensitive to systematic
  miscalibration** — a model can have c=0.8 and still be useless if probabilities are
  systematically wrong or the operating threshold sits outside the prediction range. Always
  pair discrimination with calibration; report decision-analytic measures when the model
  drives action. (Steyerberg et al. 2010,
  [PMC3575184](https://pmc.ncbi.nlm.nih.gov/articles/PMC3575184/).)
- **[VERIFIED]** **Brier score captures calibration *and* discrimination together** and can be
  scaled `1 − Brier/Brier_max` to a 0–100% range. (same source)
- **[VERIFIED]** **Calibration is (mostly) a monotonic re-mapping**: it improves Brier/log-loss
  while leaving precision/recall/F1 unchanged — so ranking metrics *cannot detect or reward*
  calibration quality; you must measure it directly with a reliability diagram.
  **[CORRECTED]** one nuance: **isotonic** calibration can slightly change ROC-AUC (it
  introduces ties); **sigmoid/temperature** scaling is strictly monotonic and preserves
  ranking. (scikit-learn
  [calibration docs](https://scikit-learn.org/stable/modules/calibration.html).) → our
  temperature recalibration is the rank-preserving choice. ✅

## 3. Imbalance handling — the SMOTE trap (directly relevant to us)

- **[VERIFIED]** **SMOTE produces the worst-calibrated probabilities** of the methods tested —
  Brier **0.078 vs 0.058** baseline, and the highest log-loss — because synthetic oversampling
  distorts the base rate the model learns. **Decision-threshold tuning leaves calibration
  untouched** (Brier unchanged at 0.058) because it's a post-hoc adjustment. (arXiv
  [2409.19751](https://arxiv.org/pdf/2409.19751).)
- **[VERIFIED]** Across **~9,000 experiments (15 models × 30 datasets × 4 scenarios)**,
  **decision-threshold calibration gave the best mean F1 in 10/15 models.**
- **[CORRECTED]** The paper does **not** brand SMOTE a universal anti-pattern (it was best on
  ~30% of datasets); it recommends testing several. **But for a project that needs calibrated
  probabilities, the calibration-degradation finding means SMOTE is the wrong default for us.**
  → We correctly **never oversample**; our cure model handles the structural-zero mass
  honestly instead. ✅

## 4. Leakage — the #1 reproducibility killer

- **[CORRECTED]** Kapoor & Narayanan document a leakage-driven reproducibility crisis across
  **20 reviews / 17 scientific fields, affecting 294 papers** (the 2023 *Patterns* figure; an
  earlier preprint said 329). (Kapoor & Narayanan, *Patterns* 2023,
  [S2666-3899(23)00159-9](https://www.cell.com/patterns/fulltext/S2666-3899(23)00159-9).)
- **[VERIFIED]** Their **taxonomy of 8 leakage types in 3 families**: **[L1]** no clean
  train/test separation (no test set, *preprocessing on train+test*, *feature selection on full
  data*, duplicates); **[L2]** illegitimate/proxy features (a feature that encodes the target);
  **[L3]** test set not from the distribution of interest — **including temporal leakage**.
- **[VERIFIED]** **Temporal leakage** is explicitly: for a future-outcome task, the test set
  must not contain data dated *before* the training data, and **k-fold CV on temporal data is a
  named instance** of this error. **Preprocessing (imputation, over/under-sampling) on the full
  dataset before the split is leakage** (oversampling-before-splitting is the canonical example).
  → This is exactly the discipline `feature_provenance()` + publication-time-only features
  enforce in our repo. ✅
- **[VERIFIED]** **Sliding-window/sequence construction before the split is itself temporal
  leakage** — build sequences *within* each partition. Plain 10-fold CV on time series inflated
  apparent accuracy by **up to 20.5% RMSE** vs <5% for chronological splits. (arXiv
  [2512.06932](https://arxiv.org/pdf/2512.06932).)

## 5. Cross-validation for time-ordered / overfitting-prone data

- **[VERIFIED]** **Combinatorial Purged CV (CPCV)** beats K-Fold, Purged K-Fold, and
  Walk-Forward at controlling backtest overfitting (lower Probability of Backtest Overfitting,
  higher Deflated Sharpe) by producing a *distribution* of out-of-sample paths instead of one.
  (Knowledge-Based Systems 2024,
  [S0950705124011110](https://www.sciencedirect.com/science/article/abs/pii/S0950705124011110);
  López de Prado / [Purged CV](https://en.wikipedia.org/wiki/Purged_cross-validation).)
- **[VERIFIED]** **Single-path Walk-Forward**, though temporally honest, has **high variance**
  (results hostage to one historical path) and weaker stationarity than CPCV. → our rolling
  origin is the right family but is single-path; **a purged+embargoed multi-path scheme would
  give tighter, less regime-dependent estimates.** ✏️ candidate upgrade to `backtest.py`.
- **[REFUTED]** "Blocked CV *outperforms* 10-fold for autocorrelated data" — the cited Liu
  (2024) paper actually found **no substantial difference** between them for the models tested.
  The *general* principle that shuffled k-fold is inappropriate for non-exchangeable data still
  holds (Bergmeir & Benítez), but don't cite this paper for a performance win.
  ([bmsp.12330](https://bpspsychub.onlinelibrary.wiley.com/doi/10.1111/bmsp.12330).)
- **[VERIFIED]** For survival models, evaluate with **censoring-aware metrics together** —
  IPCW-corrected C-index, time-dependent AUC, Integrated Brier Score — because **plain
  Harrell's concordance is biased under censoring**. (arXiv
  [2510.24473](https://arxiv.org/pdf/2510.24473).) ✅ we use C-index + IPA/Brier; ✏️ add Uno's
  IPCW C-index + time-dependent AUC explicitly.
- **[PRIMARY/UNCERTAIN]** Claims that the IPCW-Brier can deviate 0.2–0.3 from truth at small
  N, and that survival HPO needs nested CV, are *directionally* right but the specific figures
  weren't confirmable in the source ([PMC11785332](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11785332/)).
  Treat as "small-N survival evaluation is noisy — use nested resampling and report CIs."

---

## 6. The canonical HUMAN mistakes (checklist)

| Mistake | Why it bites | Guard |
|---|---|---|
| Preprocessing fit on full data before split | Train sees test statistics → optimistic | fit inside CV fold / Pipeline |
| Shuffled k-fold on temporal data | future leaks into past (≤20.5% inflation) | rolling-origin / purged CV |
| Target leakage / proxy feature | a covariate encodes the outcome | provenance audit per feature |
| Optimizing accuracy/ROC-AUC on rare events | misses calibration; rate-sensitive | PR-AUC + Brier + reliability |
| SMOTE/oversample for calibrated probs | wrecks calibration (Brier 0.078 vs 0.058) | threshold tuning + proper scoring |
| Tuning on the test set / repeated peeking | multiple-comparisons overfit | nested CV, touch test once |
| No baseline | can't tell if the model adds anything | dumb baseline always reported |
| Single headline metric, no CIs | hides variance, esp. at N≈400 | multi-metric + bootstrap CIs |
| Survivorship / distribution shift ignored | test ≠ deployment population | temporal/external validation |
| Over-trusting feature importance | unstable, leakage-driven importances | permutation tests, ablation |

## 7. Mistakes specific to AI / LLM-generated modeling code

These are the failure modes most likely in *this* codebase if generated quickly. None are
"verified by a paper" — they're the practitioner-consensus failure list, sharpened by §4's
leakage taxonomy:

1. **Silent `scaler.fit(X)` / `encoder.fit(X)` before the split** — the most common
   LLM-emitted leak; wrap in a `Pipeline` so it fits per-fold.
2. **Engineered-feature target leakage** — e.g. a feature computed using post-event data
   (our entire `feature_provenance()` discipline exists to prevent exactly this). ✅
3. **Copy-pasted `KFold`/`cross_val_score` on time-ordered data** — leaks future→past; must be
   `TimeSeriesSplit`/rolling-origin.
4. **Reporting in-sample / training-fold metrics as if held-out** — always evaluate on the
   locked test split.
5. **Fabricated or hand-waved metrics** — numbers stated without a runnable cell that produced
   them. Our rule: *evidence before assertions* — every metric in a report must come from
   `metrics.json`, not prose.
6. **Fancy model over the correct simple one** — Iannone (report 1) found plain logistic
   regression won under honest temporal CV; EPSS's gains came from *features*, not model
   complexity. We already run 8+ model families — bias toward *fewer models, better
   features/labels.* ✅ (matches `inwild-ceiling-is-data-limited`).
7. **No seeds / non-reproducibility** — set and record `random_state` everywhere.
8. **Hallucinated hyperparameters / API misuse** — verify against the library's actual signature.
9. **Over-engineering** — more pipeline than the ~400-event signal can support.
10. **Declaring success without running** — claim "fixed/passing" only after the command shows
    green. ✅ (your `verification-before-completion` discipline.)
11. **Ignoring calibration** — shipping ranks as if they were probabilities.

---

## 8. Leakage post-mortem — how to detect it *after* the fact

- **Too-good-to-be-true metric** → first suspect leakage, not brilliance (esp. AUC ≫ what the
  ~400-event ceiling allows).
- **Permutation/label-shuffle test**: shuffle y; any skill that survives is leakage or a bug.
  ✏️ `backtest.py` already supports a permutation null — extend it as a standing guard.
- **Ablation**: drop a suspect feature; a large unexplained drop flags a proxy/leak.
- **Temporal ablation**: train only on strictly-past data; a big gap vs random-CV = temporal leak.
- **Feature-timing audit**: for every feature, ask "was this knowable at the clock origin?" —
  the `feature_provenance()` `leakage_status` column is exactly this check. ✅

---

## 9. Bottom line for *this* project

You are already defended against most of the high-severity items (locked temporal split,
provenance-audited publication-time features, rolling-origin backtest, no oversampling,
calibration + Brier, bootstrap CIs). The evidence-backed **upgrades worth making**:

1. ✏️ **Report PR-AUC + reliability curves + Uno's IPCW C-index / time-dependent AUC** on the
   in-wild head (count-robust, censoring-aware, benchmarkable vs EPSS).
2. ✏️ **Move single-path rolling-origin → purged+embargoed multi-path (CPCV-style)** for
   tighter, less regime-dependent estimates.
3. ✏️ **Make the permutation-null + feature-timing audit a standing CI gate**, not an ad-hoc check.
4. ✅ **Keep resisting model proliferation** — the ~400-event ceiling means the next win is
   features/labels (report 1), not a 9th model. The metric literature (N≈400 < 1000-event AUC
   threshold) says the same: more signal, not more model.
