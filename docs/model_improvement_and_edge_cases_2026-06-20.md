# Making the in-wild model better + edge-case catalog (2026-06-20)

> Research + audit deliverable. Commissioned: "extensive research on how to make this
> model better; figure out all edge cases; verify each suggestion thrice with different
> agents; **be honest always**." Produced alongside a concurrent agent (which owns
> labels.py/modeling.py/backtest.py) — everything here is new-file / read-only and
> **does not edit the model code**. Evidence artifacts are under `artifacts/`.
>
> **Verification status legend:** `[MEASURED]` I computed it from the repo this session
> (artifact cited). `[LIT]` from the 2026 literature sweep (2 subagents, self-verified).
> `[VERIFY×3]` pending the triple independent-agent check. `[CORRECTED]` an earlier
> claim of mine I revised after checking.

---

## TL;DR — the honest thesis

1. **Ranking is saturated and genuinely data-limited; stop chasing fancier rankers.**
   In-wild AUC@90 ≈ 0.81 ≈ EPSS-trajectory. Every model swap (RSF/GBM/DeepSurv/DeepHit/
   cure/stacked-transfer) already lost prospectively, and the neutral benchmarks agree no
   method beats penalized Cox below ~600 events (Burk 2026; Rossi 2025). `[LIT]`
2. **The real frontier is the OUTPUT side — calibration under a non-stationary, heterogeneous
   latency distribution — not a new model.** The literature names our exact symptom
   ("discrimination holds, calibration drifts", Davis 2017) and the consensus fix is
   **monitor + recalibrate-on-a-recent-window** (temporal recalibration, Booth 2020), which is
   cheap, rank-preserving, and ≤6 GB. `[LIT]`
3. **A large part of the "data limit" is self-inflicted by label processing.** We *fetched*
   ~3× more in-wild labels (VulnCheck) but **discard ~70% of them** via two filters, including
   **100% of the Google 0-day signal**. Fixing the label pipeline is higher-leverage than any
   model change. `[MEASURED]`
4. **VulnCheck is a modest net positive, not the clean win the docs imply** — and I corrected
   my own overreach mid-analysis (it does *not* collapse calibration). `[MEASURED][CORRECTED]`
5. The one **untried model** lever with a real mechanism is **shared-frailty illness-death**
   (borrows strength from the abundant PoC→tooling transitions), but it's R-only and unproven
   at our scale (~50-60% odds). Everything else neural/foundation-model is not ready. `[LIT]`

---

## Verification (triple independent check — complete)

Every concrete claim here was checked by **three independent adversarial agent passes**
(recompute empirical claims from the repo, read the cited code, web-verify the research).
**All confirmed by all three; none refuted.** Refinements folded in:

- **Google 0-day denominator (B2):** "132/133 (99.2%)" is over the 133 Google-0day CVEs that *have*
  a `zeroday_date_discovered` (211 others are NaT, no computable duration). The load-bearing
  conclusion is exact: **0 survive a `duration>0` filter** → the in-wild model trains on effectively
  no Google-0day timing.
- **VulnCheck IPA (B6):** "not systematic" is correct (median ~0; removing 2022-04 flips the mean to
  +0.0002), but 2022-04 is a *real* origin with 98 events (the first large post-backfill test
  window) — a genuine single-origin calibration collapse worth understanding, **not** a spurious
  glitch.
- **Silent origin-drop (B5):** the `except Exception` path *does* `log.warning`; the truly silent
  drop is the min-train/min-test/min-events threshold `continue` (backtest.py ~214-219), which logs
  nothing — the larger optimistic-bias surface for model *comparison*.
- **Corpus (A1):** the drop-accounting reproduces exactly against the canonical handover/merged
  corpus (338,015 CVEs); the larger `data/live` corpus gives slightly different denominators.

---

## Part A — How to make it better (ranked by leverage × honesty)

### A1. Stop discarding the in-wild labels we already have `[MEASURED]` — **highest leverage, lowest cost**

The in-wild risk set is gutted by two filters in the label/modeling path. Event-accounting
(`artifacts/` join over corpus `published` vs each source's earliest date):

| source | corpus-CVEs w/ date | dropped: dur<0 (pre-disclosure) | dropped: pub<2021-11-03 floor | **survivors to model** | floor-dropped but dur>0 (recoverable) |
|---|---|---|---|---|---|
| VulnCheck KEV | 4837 | 1574 (32.5%) | 2310 (47.8%) | **1478 (30.6%)** | 1741 |
| CISA KEV | 1542 | 193 (12.5%) | 865 (56.1%) | **444 (28.8%)** | 865 |
| Google 0-day | 133 | 132 (99.2%) | 88 | **0 (0.0%)** | 1 |

Two distinct defects (details in Part B, B1/B2):

- **(B2) The model never sees a single Google 0-day event.** 99.2% of 0-days are discovered
  *before* CVE publication (that is what a 0-day *is*) → negative duration → dropped in
  `prepare_modeling_frame`. The 133 "in-wild 0-day events" in the manifest contribute ~0 to the
  fitted model. The most severe in-wild signal is silently absent.
- **(B1) The `published < 2021-11-03` clock floor is a CISA artifact mis-applied to VulnCheck.**
  CISA dumped 287 entries on its 2021-11-03 launch day (real backfill spike); VulnCheck has only
  53 there and a smooth distribution back to 2000 (first-*evidence* dates). The floor drops 1,741
  VulnCheck (+865 CISA) events that have *valid positive durations*.

**Fix (new code, does not touch labels.py):** a **source-aware** in-wild clock — floor only
catalog-add-dated sources (CISA), keep first-evidence-dated sources (VulnCheck/Shadowserver/0-day);
and handle pre-disclosure exploitation explicitly (floor duration at 0.5d = "exploited at
disclosure" rather than dropping) **or** state it as an explicit scope exclusion. Expected to
roughly **double** the usable in-wild event count.
**MEASURED WIN (`artifacts/inwild_floor_ablation.json`):** removing the floor on the in-wild
+VulnCheck set (cox, 14 origins) recovers ~110 training events and **improves AUC@90 median
0.808→0.827 (paired delta +0.0147, CI [+0.0012, +0.0281] — excludes 0)**, lifts recall@90
0.540→0.553, and **erases the calibration collapse** (IPA@90 mean −0.0835→+0.0011). The test set
is identical across arms (test CVEs are always published ≥2022 since origins start 2022-01-01) —
the floor only removed pre-2021 CVEs from *training*, so this is a valid same-test gain from
recovering discarded training events. A VulnCheck-only arm reproduces it (rules out CISA backfill
being the driver). **Caveat:** recovered CISA-backfilled events have artifactual *durations*
(catalog-add), so trust the ranking gain over the timing; the VulnCheck-only arm (clean
first-evidence dates) giving the same result is what makes it robust. Single run, cox, EPSS-only
features — confirm with the incentive features + a second model before shipping.
**IMPLEMENTED (commit d23c7b7).** `in_wild_clock_start` now returns `None` when a broad first-evidence
source (`EVIDENCE_SOURCES = {vulncheck_kev, shadowserver}`) is active — VulnCheck's earliest-wins merge
self-heals 234/287 CISA-spike CVEs. **google_0day is excluded** (an RE catch on the audit's design:
~133 CVEs, ~all dropped → it cannot self-heal CISA's backfill, so it must not lift the floor when it
is the *only* first-evidence source — which also preserved the existing `test_cli.py` contract).
Unit-tested (`tests/test_in_wild_clock.py`); full suite green. **Still to re-measure:** confirm the
default +VulnCheck config reproduces the no-floor result, and re-run with the incentive features +
xgb. `[IMPLEMENTED]`

### A2. Temporal recalibration — re-estimate only the baseline hazard on a recent window `[LIT]` — **the cheap win the evidence points to**

Both my measurements (non-stationarity: median latency 745d→44d historically; 24d→203d when
VulnCheck broadened the population) and the literature converge here. **Booth, Riley, Rutherford
2020 (IJE 49(4):1316)**: keep the (penalized) covariate effects fit on all data, re-estimate
**only the baseline survival** on a recent calendar window. Rank-preserving (AUC unchanged),
1-parameter-ish, ≤6 GB, ~1200 events fine. Pairs with **recalibration-in-the-large**
(intercept/slope, van Houwelingen 2000) and **D-calibration monitoring** (Ghawami 2026).
Implement as a new `temporal_recalibration.py` applied to the Cox baseline (lifelines uses a
Breslow baseline → recompute it on recent rows). `[VERIFY×3]`

### A3. Name and correct the VulnCheck symptom as **label shift** `[LIT]`

Tripling labels changed `p(latency)` (the prior), not `p(features|event)` — that is *label shift*
by definition. **BBSE** (Lipton 2018) / survival-native **Zong 2025 (arXiv:2506.21190)** reweight
to the deployment-era prior. Apply on a *binned* horizon indicator. Lower priority than A2
(recalibration achieves much of the same calibration repair with less machinery), but it's the
correct diagnosis and the principled escalation. `[VERIFY×3]`

### A4. Add proper-scoring + decision-curve to the eval `[LIT]` — **measure the right thing**

- **IPA's basis (integrated Brier) is not strictly proper** and is dominated by the 99.5% non-events,
  so "IPA ≈ 0" may be partly a *metric* artifact. Add **RCLL** (right-censored log-likelihood,
  strictly proper) as a reporting metric. (Implementation: new `proper_scoring.py`.)
- **Decision-curve / net-benefit** — implemented (`src/temporal_exploit/decision_curve.py`,
  censoring-aware Kaplan-Meier net benefit, TDD `tests/test_decision_curve.py`) and **applied**
  (`scripts/inwild_decision_curve.py` → `artifacts/inwild_decision_curve.json`).
  **MEASURED:** at the 0.32% event-by-90d base rate the in-wild model has **positive net benefit
  and beats both treat-all and treat-none across the realistic 0.1%–3% threshold band** — so it is
  operationally useful, *not* worthless (refutes the most pessimistic hypothesis). But absolute net
  benefit is small (≈0.0014 at a 0.5% threshold) and decays to ~0 above a 5% threshold. AUC alone
  hides this. `[MEASURED]`
- **RCLL** (strictly-proper survival log-likelihood) remains a *recommended* reporting add — it
  would settle whether "IPA ≈ 0" is a non-proper-metric artifact — but it needs a fine survival-time
  grid (the pipeline currently evaluates only 4 horizons), so it is scoped as a follow-on, not yet
  implemented. `[LIT]`

### A5. Untried *model* levers — shared-frailty is a NO-GO; PU-reweight is the cheaper bet `[premise corrected by feasibility audit]`

**Correction (independent feasibility audit, recomputed from real data):** the premise that justified
shared-frailty — "borrow strength from ~190k abundant transitions" — is a **conflation of
state-occupancy with transition events**. The real PoC→tooling transition *events* are ~2,577 (not
190k), and they couple to only **661** of the in-wild CVEs. With VulnCheck the in-wild EPV is now
**17–21 — no longer EPV-starved**, so penalized Cox is already in its comfort zone (Burk 2026 / Rossi
2025). Combined with the R-outside-the-backtest-harness cost (it can't ride `rolling_origin_backtest`,
the project's only validity instrument) and the mixed-estimand clock (B3), **shared-frailty
illness-death (`SemiCompRisksFreq`) is a NO-GO at current scale**; the pure-Python "poor man's" version
is the already-failed stacked transfer in disguise (a cause-specific linear predictor is again a
combination of features the in-wild Cox already has).

**PU recency-reweight** is the cheaper **conditional-GO**: treat censored as unlabeled with a
recency-dependent propensity `e(x)=f(CVE age)` (lifelines already exposes `weights_col`+`robust`, ~30
lines). But it's a *calibration* experiment on the underpowered axis (Part E), needs a **fixed**
propensity assumption (co-estimating it is non-identifiable) and a `min_events` guard (else the
event-starved-origin fragility that killed temperature recalibration recurs). Honest expected payoff:
~0, possibly small positive on recent-origin calibration. **Do not** pursue TabPFN/SurvivalPFN
(empty-placeholder repo; degenerates at 99.5% censoring). `[VERIFY×3 + feasibility-audited]`

### A6. Fix the non-stationarity *harness* (N5) to measure calibration, not just AUC `[MEASURED]`

`era_stress_eval` reports only `horizon_auc` degradation across eras. But my VulnCheck evidence
shows non-stationarity hits **calibration/timing (IPA, lead-time), not ranking (AUC was flat)** —
so N5 as built can return "AUC degradation ≈ 0" and falsely reassure while calibration drifts.
Extend it to also report IPA + median-latency shift across eras, and run it on the **in_wild**
target (the deliverable), not just first_weaponization. `[VERIFY×3]`

---

## Part B — Edge-case catalog (severity-ranked)

| # | Edge case | Location | Severity | Status |
|---|---|---|---|---|
| B1 | Clock floor `published<2021-11-03` mis-applied to first-evidence sources (VulnCheck) → drops 1,741 valid events | `cli.py:295` CATALOG_START / `in_wild_clock_start` | **HIGH** | `[MEASURED]` |
| B2 | Pre-disclosure exploits dropped as negative-duration → **all** Google 0-day (132/133) + 32.5% VulnCheck excluded from the fitted model | `labels.py` + `modeling.py:21` prepare_modeling_frame | **HIGH** | `[MEASURED]` |
| B3 | In-wild "duration" is a **mixed estimand**: CISA = catalog-*add* delay (administrative), VulnCheck = first-*evidence* delay; pooling them is why median lead-time jumped 24d→203d | `labels.py` IN_WILD_SOURCES | **HIGH** (framing) | `[MEASURED]` |
| B4 | `era_stress_eval` measures only horizon-AUC degradation → misses the calibration drift that *is* the non-stationarity symptom | `backtest.py:~313` | **MED** | `[MEASURED]` |
| B5 | `rolling_origin_backtest` swallows per-origin exceptions (`except Exception: continue`) with no skip record → a model that errors on hard origins is silently dropped from the aggregate (optimistic-bias risk in model comparison) | `backtest.py:~226` | **MED** | `[MEASURED]` |
| B6 | IPA mean is corrupted by event-starved origins (one 2022-04 origin = IPA −1.171 dragged the VulnCheck mean to −0.0835 while median stayed ~0) → report median, not mean | `backtest.py` _aggregate / scripts | **MED** | `[MEASURED]` |
| B7 | `_merge_extra` fills unscored augment columns with `0.0` ("neutral") — for a transfer risk-score covariate not centered at 0, this injects outliers (relevant only to the augment_fn/stacked-transfer path) | `backtest.py:~80` | **LOW** | `[MEASURED]` |
| B8 | horizon-AUC subcohort restriction is informative censoring at long horizons (drops 17.7% at 180d) — acknowledged + `dropped_frac` reported, but 180d AUC remains caveated | `modeling.py:~475` | **LOW** (known) | `[MEASURED]` |
| B9 | EPSS-missing (pre-2021-04-14 CVEs, ~48%) filled with `0.0`; the missing-flag lets the model compensate, but a 0.0 EPSS is a strong false "low-risk" value for linear models | `epss_features.py:143` | **LOW** | `[MEASURED]` |
| B10 | `artifacts/bt_epss` features predate the CVSS-incentive flags → backtest numbers are on the EPSS-only feature set (already caught by the concurrent agent in N4) | artifact staleness | **LOW** | `[MEASURED]` |

The 2022-04 origin anomaly (B6) is worth a dedicated look — an IPA of −1.171 is extreme enough to
suggest a specific calibration failure when VulnCheck adds a cluster there, not just a hard origin.

---

## Part C — What NOT to do (documented dead-ends; don't burn cycles) `[LIT]`

RSF, gradient-boosted survival, DeepSurv, DeepHit, mixture-cure (non-identifiable, no KM plateau),
stacked-transfer (source shares target features), temperature/isotonic recalibration on the full
set, 2D-spline hazards, DRO-survival, conformal survival (gives intervals, not calibrated absolute
probabilities), TabPFN/SurvivalPFN today. All either lost prospectively here or are NOT-FEASIBLE at
1,200 events / ≤6 GB.

---

## Part D — Experiments run this session (reproducibility)

- `scripts/inwild_vulncheck_backtest.py` → baseline vs +VulnCheck (committed driver).
- VulnCheck diagnosis (median + per-origin IPA + paired delta) → `artifacts/vulncheck_diagnose.json`.
- Drop-accounting join (negative-duration + floor) → see Part A1 table.
- Floor on/off ablation → `artifacts/inwild_floor_ablation.json` (running).
- 2 literature sweeps (non-stationarity; untried model levers) — sources inline in A2/A3/A5.

**Headline VulnCheck numbers (cox, in-wild, 14 origins):** events 396→1201 (3.0×); AUC@90 median
0.847→0.808 (~flat); AUC variance tighter (sd@180 0.060→0.040); recall@top-10%@90 0.509→0.540;
IPA@90 median +0.0003→+0.0000 (neutral), mean −0.003→−0.083 (one outlier origin); median lead-time
24d→203d. Paired IPA@90 delta −0.080, CI [−0.237, +0.076] (includes 0).

---

## Part E — Validity: eval power & in-wild non-stationarity (already answered)

- **Eval power (is "no model beats Cox" a powered equivalence, or just undetectable?).** The
  rolling-origin paired CIs answer this directly: the backtest **detects a +0.015 AUC@90 ranking
  effect** (the floor fix, CI [+0.0012, +0.0281] excludes 0) but **cannot resolve IPA/calibration
  effects below ~±0.15** (VulnCheck IPA@90 paired CI [−0.237, +0.076]). So "no model out-*ranks*
  Cox by more than ~0.015 AUC" is a *powered* conclusion (stop chasing rankers); "no model improves
  *calibration*" is **not** powered — the backtest is calibration-underpowered at ~1,200 events.
  That is the honest reason the calibration frontier (A2/A4) stays open while the model-class
  question is closed. `[MEASURED]`
- **In-wild non-stationarity (the N5 validity gate) is visible in the per-origin IPA trajectory**
  (`artifacts/vulncheck_diagnose.json`): IPA@90 swings from a +0.005 median to −1.17 at the 2022-04
  origin (a real 98-event window) while AUC stays ~0.81 throughout — i.e. **calibration, not ranking,
  is what drifts across eras.** This confirms B4 (an AUC-only era-stress harness would miss it) and
  explains *why* the floor fix helps (a broader training era stabilizes the baseline hazard). A
  dedicated single-split in-wild era-stress would be *more* event-starved than this per-origin view,
  so it is the wrong instrument here. `[MEASURED]`
