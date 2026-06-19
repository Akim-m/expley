# Time-to-Weaponization (TTW) Prediction — Research & Modeling Plan

**Author role:** Principal CTI Scientist (vulnerability-exploitation forecasting).
**Date:** 2026-06-20. **Status:** strategy + phased roadmap. Self-reviewed; **5 reverse-engineering rounds
applied — findings and fixes are in §16 (honest, not a placeholder).** Complements
`research_competitive_methods_2026-06.md`, `research_model_building_pitfalls_2026-06.md`,
`poc_content_features_plan.md`, and `CLAUDE.md`.

Claims are tagged **[E]** evidence, **[A]** assumption, **[H]** hypothesis, with confidence. Register: §15.

---

## 0. TL;DR — the thesis

The strongest lever is **NOT a fancier architecture**. The 2025–2026 evidence (§2) and our own data (§3)
give four thrusts, in priority order:

1. **Expand and sharpen the in-the-wild label set** (lift the ~396-event ceiling). VulnCheck KEV
   (**4,969 rows, already on disk**) ~triples the in-wild base vs CISA KEV alone (1,623). Highest impact,
   lowest risk. **[E, high]**
2. **Mine the already-present `epss_history` (375M daily readings) for the EPSS *trajectory*** — velocity,
   acceleration, percentile dynamics, threshold-crossing time. It is on disk, leakage-safe when restricted
   to readings ≤ origin, and cheap via the new `_iter_epss_batches` date-pushdown. **But** see the
   circularity caveat (§5.1): EPSS is itself an in-wild model, so its features partly *distill* EPSS rather
   than add new signal — every EPSS-derived gain must be measured **against an EPSS-only baseline**. **[E, high]**
3. **Model the regime shift, not a stationary world.** TTE collapsed ~745d (2020) → ~44d avg (2025); ~32%
   of KEV weaponized within 24h. The target has a **large point-mass at/near t=0** and is **non-stationary
   and accelerating** (LLM-assisted exploit dev). This dictates the loss, censoring handling, a **≤24h
   head**, and the validation design more than the model class. **[E, high]**
4. **Add a few forward-looking, leakage-safe *speed* features** beyond EPSS: attacker-incentive,
   exposure/prevalence, leakage-timed social/threat-intel, and an offline **LLM-exploitability** probe
   (with the anachronism caveat, §5.2). **[E/H, med-high]**

**Recommended core architecture:** a **calibrated competing-risks survival ensemble** (AFT [CatBoost/
XGBoost] + penalized Cox + mixture-cure, stacked on out-of-time predictions) with a **discrete-time hazard
head for the t≈0 mass**, **conformal prediction intervals**, per-cohort calibration, and **two operating
points** (instant-at-publication vs landmark-updated). Deep/GNN/Transformer/LLM-predictor models are
**backtest challengers judged by `paired_origin_deltas`** — expected *not* to beat the tabular ensemble at
current scale, and required to prove a paired-CI-excludes-0 win before adoption.

**Program success/kill criterion [A, high]:** declare progress only when the T-inwild head beats an
**EPSS-only baseline** by a paired-CI-excludes-0 margin on **PR-AUC at h=7 and h=30** out-of-time. If, after
label expansion (thrust 1) + features (2–4), the CI still includes 0, **declare the data ceiling and pivot
effort to label acquisition**, not modeling — exactly what `inwild-ceiling-is-data-limited` predicts.

---

## 1. Problem definition (get this right first)

"Weaponization" is overloaded; conflating targets is the #1 way to an indefensible model.

| Target (clock origin = `published`) | Event | Observable label volume | Quality |
|---|---|---|---|
| **T-tooling** | earliest PoC / Metasploit / Nuclei / ExploitDB | ~190k PoC + 30k ExploitDB + 3–4k MSF/Nuclei | high volume, **PoC-dominated (~97%)** |
| **T-inwild** | earliest CISA-KEV / VulnCheck-KEV / Google-0day / Shadowserver | ~5–6k combined pre-dedup; ~396 clean observable-era today | **the operationally meaningful target** |
| **T-cascade** | PoC→MSF, PoC→KEV … (competing risks) | per-transition | where PoC-content features are leakage-legal |

**Recommendation [A, high]:** model all three as **distinct heads on a shared feature substrate**;
**T-inwild is the headline**; use T-tooling/T-cascade as **auxiliary/transfer signal** for the data-starved
in-wild head (multi-task / stacked transfer — `inwild_stacked_transfer.py` exists). Never quote a
PoC-dominated T-tooling number as in-wild performance (the build-time `event-source dominance` warning guards this).

**Two operating points (operational reality, R4):** (a) **instant scoring at publication** — only features
knowable at t=0 (CVSS, CWE, CPE, refs, attacker-incentive); EPSS/PoC history usually *not yet available*;
(b) **landmark-updated scoring at t+L** — adds EPSS trajectory + early tooling. We already have the
landmark infra (`landmark.py`, `restart_clock`). Both must be evaluated; the instant head is the harder,
more valuable one given the collapsing window.

**Primary metric:** a **panel**, not a scalar (§7) — single-AUC headlines forbidden.

---

## 2. Evidence base — 2025–2026 SOTA delta

- **EPSS v4 (FIRST, 2025-03-17)** — ROC-AUC ≈0.838; gains from **~12k exploited CVEs/month coverage (vs
  ~2k v3)** + **malware-intel + EDR telemetry**, CWE→**CWE-1400 top-22**, temporal features. Sensor-based
  ground truth → label under-counting. **[E]** → labels+features dominate; adopt CWE-1400; report in EPSS units.
- **Collapsing window** — TTE 745d(2020)→84d(2021)→~6d(2023)→**~44d avg(2025)**; **32.1% KEV ≤24h**
  (↑ from 23.6%); ~28% ≤1 day. **[E]** → t≈0 mass, non-stationarity, fast head.
- **LLM exploit/PoC gen** — working PoCs **8–34%** (DeepSeek-R1 > GPT-4), **68–72%** with adaptive
  reasoning; LLM-CVX / ZeroDayBench / Patch-to-PoC. **[E]** → LLM-exploitability *speed* feature + drift driver.
- **Dark-web/social early-warning** — forums/Telegram/Discord/markets; Sabottke ~10× precision, ~2-day
  lead. **[E]** → proven lead-time family, leakage-timing + data-access gated.
- **Temporal GNN** — recent literature dominated by **adversarial-fragility** (HIA transfers across TGN/
  JODIE/DySAT/TGAT); no published TTW-GNN win. **[E, med]** → GNN is a gated hypothesis, not a default.

Sources §17.

---

## 3. Central scientific challenges (the hard part is here, not the model)

1. **Label scarcity + ceiling (T-inwild)** — ~396 clean events; more model ≠ more skill. **[E]**
2. **Non-stationarity/drift** — fit on 2021–23 under-predicts 2025+; random CV is actively misleading. **[E]**
3. **t≈0 / negative-duration mass** — same-day + pre-disclosure 0-days are *structural*; a continuous
   hazard alone mis-handles the spike (needs a discrete/point-mass head). **[E]**
4. **Informative censoring** — "not yet exploited" correlates with covariates (and with **being patched/EOL**,
   a competing event). Naive KM/Cox assume independent censoring → bias. **[A, high]**
5. **Temporal leakage** — NVD back-edits, snapshot EPSS/presence; every new feature passes
   `feature_provenance()` timing audit. **[E]**
6. **Label noise/under-counting** — sensor blind spots; PoC dates are git-mining proxies. **[E]**
7. **EPSS circularity (R2)** — EPSS already encodes in-wild signal, so EPSS-derived features are partly a
   re-derivation of EPSS, not new evidence; must be isolated by an EPSS-only baseline + marginal ablation. **[E, high]**
8. **Feedback/strategic adversary** — publishing predictions shifts behavior; KEV lags exploitation.
   Documented validity caveat, not modeled now. **[A, low]**

---

## 4. Data strategy (the #1 lever)

**4.1 In-wild label expansion (do first).** Mostly on disk:
- **VulnCheck KEV (4,969, present)** → fold into `IN_WILD_SOURCES` (wired via `fetch/vulncheck.py`); dedup
  vs CISA KEV by CVE + earliest date. **[E]**
- **CISA KEV (1,623), Google 0-day (404), Shadowserver (wired)** — keep; KEV `dueDate`/ransomware-flag as
  *covariates*, not labels. **[E]**
- **Cost-gated candidates:** GreyNoise/honeypot, Censys/Shodan exploited tags, Talos/Unit42/Mandiant feeds.
  **License/governance caveat (R4):** commercial-feed labels may be non-redistributable — verify TOS before
  baking into a shareable dataset. **[H, med]**
- **ExploitDB *verified* (30k)** — a *tooling* label/feature, **not** in-wild.
- **Expected effect [H, high]:** ~396 → ~1.5–4k observable-era in-wild events after dedup/clock-filter →
  tighter CIs and the first real shot at beating the EPSS-augmented baseline.

**4.2 Exploit the already-present EPSS history (cornerstone, on disk — R1).** `epss_history-001.parquet` /
`data/live/epss_history.parquet` (375M daily readings, 2021-04-14→now, one row group/day). Beyond the
single `epss_at_publication` we already compute, mine the **trajectory** (§5.1) per CVE over readings
**dated ≤ the prediction origin** (instant) or ≤ landmark (updated). Extraction is cheap and memory-flat via
the new `epss_features._iter_epss_batches` date-pushdown (skips out-of-range row groups; ~300 MB RSS). This
is the richest under-used dataset we own — but governed by the circularity caveat (§5.1).

**4.3 Feature data sources (leakage-timed).** Internet-exposure/prevalence (Shodan/Censys counts ≤ origin —
paid/rate-limited, cost-gate), CWE-1400 mapping, CPE applicability, reference-tag taxonomy, social/forum
first-mention timestamps (admissible only if dated ≤ origin), offline **LLM-exploitability** probe (§5.2).

**4.4 Efficiency + compute budget.** Per `optimize-data-loading`: column projection + date pushdown on every
load; the EPSS pushdown is the template. Hard ceiling **6–8 GB RAM / 7 GB VRAM**; **RSF/GNN/LLM are
compute-heavy — sample/cap first, `free -g` before heavy steps, never RSF on the full corpus.**

---

## 5. Feature roadmap — engineered for *speed*, not just *likelihood*

### 5.1 EPSS-trajectory family (cornerstone; mind circularity)

From `epss_history`, all restricted to readings ≤ origin (instant) or ≤ landmark (updated):
- **EPSS velocity** — slope of EPSS over the first 7/14/30 days (a steep early rise is the market's own
  fast in-wild signal — a *speed* feature). **[H, high]**
- **EPSS acceleration / curvature**, **percentile dynamics**, **time-to-cross EPSS≥{0.1,0.5}**, **early
  volatility**. **[H, med]**
- **Build path:** generalize `build_epss_at_landmark` (it already does last-in-window) to emit slope/quantile
  features over the windowed readings, reusing `_iter_epss_batches`.
- **Circularity control (R2, mandatory):** ship an **EPSS-only baseline** and a **no-EPSS ablation**
  (`inwild_feature_prune.py`); report the **marginal** lift of non-EPSS features so we don't claim
  EPSS-distillation as novel skill. Confidence on "EPSS-trajectory adds *new* signal beyond EPSS-at-pub":
  **[H, med]** until the ablation shows it.

### 5.2 Other speed features

| Family | Why *speed* | Leakage class | Cost | Conf |
|---|---|---|---|---|
| **Attacker-incentive** (ransomware-targeted product, RCE+unauth+network, pre-auth, internet-facing edge/VPN/auth device) | high-ROI → fast | pub-time safe (CVSS vector+product) | S | **[E, high]** |
| **Exposure/prevalence** (Shodan/Censys host counts ≤ origin; product ubiquity) | mass-scan targets weaponize fast | pub-time safe if scan-dated ≤ origin | M (paid API) | **[H, med]** |
| **LLM-exploitability** (offline probe: can an LLM draft a PoC from public CVE text+refs?) | technical exploitability ↑ → faster | pub-time safe **but anachronistic** | M | **[H, med]** |
| **PoC-content** (code-complexity + masked NLP) | EE's best-evidenced lift | **transition/landmark only** (`poc_content_features_plan.md`) | L (fetch code) | **[E, high]** |
| **Social/threat-intel velocity** (first-mention, mention rate, forum/dark-web hits) | Sabottke ~2-day lead | pub-time safe *iff* dated ≤ origin | M–L (access) | **[E, med]** |
| **CWE-1400 top-22 + ATT&CK chain** (chain exists) | technique class ↔ tooling speed | pub-time safe | S | **[E, med]** |

**LLM-exploitability caveats (R3/R4):** (a) **anachronism** — a 2026 LLM applied to 2021 CVEs injects
future capability; treat it as a *current-deployment* feature and, in backtests, either freeze a fixed model
or flag the temporal inconsistency; (b) **non-determinism** — fix temperature=0 + **cache** per CVE so the
feature is reproducible. **Build first only if** P1 ablation (X4) shows a paired-CI-excludes-0 lift.

---

## 6. Modeling approaches — proposed, compared, recommended

Each plugs into `rolling_origin_backtest` and is judged by `paired_origin_deltas` (CI-excludes-0 on shared
origins). The data decides.

1. **Penalized Cox PH (have)** — interpretable hazard; the baseline to beat. **[E, high]**
2. **AFT (XGBoost-AFT have; add CatBoost/LightGBM)** — models *time* directly, non-linear, censoring-aware;
   **most likely single tabular winner.** CatBoost has native survival objectives — **[A, verify]** before
   relying on it. **[E/A, med-high]**
3. **Gradient-boosted survival / RSF (have)** — competitive; **RSF RAM-heavy → prefer AFT/GBS.** **[E, med]**
4. **Mixture-cure (have)** — explicit never-weaponized mass (~94% structural zeros). Keep. **[E, high]**
5. **Discrete-time hazard with t=0 point-mass (NEW, R2)** — define precisely: a **binary head** P(weaponized
   by day 0 | x) for the same-day/0-day mass, then a **conditional discrete-time logistic hazard** per
   day-bucket for the survivors. The principled fix for the 32%-within-24h spike + the ≤24h operating head.
   **[H, high]**
6. **Competing-risks (have `competing.py`/DeepHit)** — cause-specific PoC/MSF/KEV hazards; also model
   **"patched-before-exploited" as a competing event** to address informative censoring (R2). DeepHit only
   if data grows. **[E, med]**
7. **Bayesian / conformal survival (NEW)** — distribution-free **TTW intervals**; high operational value,
   low cost. **[H, high]**
8. **Relational GNN (GAT over CVE↔CWE↔CPE↔vendor↔ATT&CK or CVE-actor-campaign)** — **unlikely to beat AFT/Cox
   at 10³–10⁴ events; adversarially fragile**. Gated hypothesis with a kill criterion; no adoption without a
   paired-CI win. **[H, low]**
9. **Transformer over the event-cascade sequence** — data-starved; defer. **[A, med]**
10. **LLM-as-predictor (POLAR-style)** — use the LLM as a **feature extractor** (narrative encoding,
    exploitability probe), **not** the predictor (an LLM point-estimate is uncalibrated + costly). **[A, high]**

**Recommended core [A, high]:** AFT (CatBoost/XGBoost) + penalized Cox + mixture-cure, **stacked via a
meta-learner on out-of-time predictions** (not naive curve-averaging); discrete-time t=0 head; conformal
intervals; per-cohort calibration (by EPSS band / era / CWE-1400). Matches data scale, handles spike+cure+
censoring, stays interpretable (SHAP), every gain survives the paired-origin CI test.

---

## 7. Evaluation & validation methodology

- **Temporal only.** Rolling-origin (have) + **purge/embargo gap** around each origin; consider CPCV to cut
  single-path variance. **Never random K-fold.** **[E]**
- **Panel:** time-dependent IPCW c-index (Uno) + **time-dependent AUC(t)** (add `cumulative_dynamic_auc`);
  **PR-AUC/AP per horizon** constructed on the **fully-observed subcohort** (positive = exploited-by-h;
  mirrors the existing horizon-AUC subcohort to avoid censoring bias — R3); integrated Brier; **calibration
  curve + ECE/slope out-of-time, per cohort** (EPSS band / era / CWE-1400 — targets the "68% regardless of
  band" critique); decision-curve **net benefit**; **lead-time-days** (have); **≤24h + 7d short heads**. **[E]**
- **Baseline ladder (R2/R3):** majority/KM null → CVSS-only → **EPSS-only** → EPSS-augmented Cox (current) →
  proposed. A new model must beat **EPSS-only** to claim novel skill.
- **Cross-model uncertainty:** `paired_origin_deltas` (have); bootstrap CI primary, Noether labeled approx.
- **Negative controls:** permutation/label-shuffle null as a **standing CI gate**; temporal-ablation leakage
  tripwire. **[E]**
- **Benchmark caveat (R3):** EPSS-v4's 0.838 is ROC-AUC on *its* cohort/horizon — comparison is **indicative,
  not apples-to-apples** (different cohort, label def, horizon).
- **Label-noise sensitivity:** retrain under simulated 10–30% wrong-negatives (EE technique). **[H]**

---

## 8. Generalization to future CVEs (non-stationarity is the headline risk)

- **Prospective holdout** on the most-recent N months; never only interpolated splits. **[E]**
- **Drift monitor with a concrete trigger (R4):** track feature/label PSI/KL per origin **and** prospective
  Brier vs a rolling baseline; **alarm + retrain when prospective Brier degrades > ~10%.** **[E]**
- **Era stress test:** train ≤2023, test 2025+ (the LLM-AEG regime) — quantify degradation (the realistic
  deployment condition); watch for the LLM-feature anachronism (§5.2). **[H, high]**
- **Cold-start (R4):** brand-new CVEs have no EPSS/PoC history at t=0 (EPSS first reading lags) → the
  **instant operating point** must score from t=0-knowable features only and use the `epss_*_missing` flag;
  new vendor/CWE → CWE-1400 category priors; report cold-CVE subgroup error explicitly. **[A, med]**

---

## 9. Experiment matrix (hypothesis · falsifier · expected · cost)

| # | Experiment | Falsifier | Expected | Cost |
|---|---|---|---|---|
| X1 | VulnCheck-KEV into in-wild labels; refit | CIs don't tighten | tighter CIs, AUC ≥ current | S, in-budget |
| X2 | EPSS-units panel on T-inwild (PR-AUC/Brier/coverage/AUC(t)) | — (instrumentation) | benchmarkable | S |
| X3 | **EPSS-only baseline + no-EPSS marginal ablation** | non-EPSS features add nothing (CI⊇0) | isolates real novel skill | S |
| X4 | **EPSS-trajectory** (velocity/accel) ablation | CI⊇0 vs EPSS-at-pub | + discrimination, lead-time | M (pushdown) |
| X5 | LLM-exploitability feature ablation | CI⊇0 | + on T-tooling/cascade | M (cached LLM) |
| X6 | Discrete-time t=0 + ≤24h head vs continuous Cox | no short-horizon Brier/PR-AUC gain | better fast calibration | M |
| X7 | Era stress (train ≤2023, test 2025+) | no degradation | quantified drop → retrain cadence | S |
| X8 | Conformal TTW intervals; coverage check | empirical ≠ nominal coverage | calibrated intervals | S |
| X9 | Purge/embargo + CPCV vs single-path | variance unchanged | tighter estimates | M |
| X10 | GNN on CWE/CPE/vendor substructure vs AFT | CI ≤ 0 (expected) | likely null → documented kill | L, RAM-risk |

Priority: **X1, X2, X3, X4, X7, X8** (high impact / in-budget) → **X5, X6, X9** → **X10** (likely-null, expensive).

---

## 10. Uncertainty, calibration, explainability

- **Uncertainty:** conformal intervals (X8) + per-model bootstrap CIs + honest n_events; separate aleatoric
  (attacker randomness) from epistemic (data-limited). **[H]**
- **Calibration:** out-of-time reliability + ECE per horizon **per cohort**; temperature (rank-preserving,
  have) primary; isotonic held-out only (overfits in-sample — documented). **[E]**
- **Explainability:** SHAP on the AFT/GBS ensemble → per-CVE *speed drivers*; validates the speed-vs-
  likelihood hypothesis; avoid post-hoc stories on unstable deep models. **[A, high]**

---

## 11. Failure modes & risks (up front)

Informative censoring bias; label under-counting (sensor blind spots); back-edit/snapshot leakage on any new
feature; **EPSS circularity** (mitigated by EPSS-only baseline); **LLM-feature anachronism + non-determinism**
(freeze/cache); social/dark-web **data-access + timing** fragility; **commercial-feed license/redistribution**
limits; GNN adversarial fragility + no-win; strategic-adversary feedback; over-claiming within-error margins
(guarded by `paired_origin_deltas`). Each phase (§13) names its specific risk + mitigation.

---

## 12. Continuous literature surveillance (operating mode)

Monthly sweep: arXiv cs.CR, USENIX/NDSS/CCS/RAID, FIRST/EPSS, CISA, vendor research (Unit42/Talos/Mandiant/
Recorded-Future/VulnCheck/Flashpoint). New method → reproduce its metric on our T-inwild panel → wire as a
backtest challenger → adopt only on a paired-CI win. Log in `research_competitive_methods_*.md`. Per
`check-for-better-methods`: **web-verify before trusting any number** (this discipline already caught two
errors in our own prior review).

---

## 13. Phased roadmap (impact × cost; respects RAM budget)

- **P0 — Labels + benchmarkable reporting (highest impact, in-budget):** X1 (VulnCheck-KEV → `IN_WILD_SOURCES`,
  TDD the dedup/earliest-date merge), X2 (PR-AUC/Brier/coverage/AUC(t) on T-inwild), X3 (EPSS-only baseline +
  marginal ablation), regenerate the in-wild head-to-head through the paired-bootstrap path. *Risk:* merge
  errors → TDD.
- **P1 — EPSS-trajectory + cheap speed features:** X4 (trajectory via `_iter_epss_batches`), attacker-incentive
  + CWE-1400, PoC-content **index-metadata P0** (`poc_content_features_plan.md`). *Risk:* leakage timing →
  provenance row + coverage assertion.
- **P2 — Distribution-aware modeling + uncertainty:** X6 (t=0 + ≤24h head), X8 (conformal), per-cohort
  calibration, CatBoost-AFT (verify survival support first). *Risk:* small-n overfit → paired-CI gate.
- **P3 — Non-stationarity hardening:** X7 (era stress), drift monitor + retrain trigger, X9 (purge/embargo+CPCV).
  *Risk:* compute → bounded multi-path.
- **P4 — Forward LLM + relational (gated, expected-null):** X5 (LLM-exploitability), X10 (GNN with kill
  criterion). *Risk:* RAM + no-win → time-boxed, drop on CI≤0.
- **Continuous:** §12 surveillance; operational SHAP + decision-curve reporting.

Each phase = its own brainstorm → spec → TDD plan (`docs/superpowers/plans/…md`); every code change under the
**5-reverse-engineering-loop** discipline.

---

## 14. What we already have (don't rebuild)

True hazard + competing-risks + mixture-cure; leakage-safe pub-time features + provenance gate; rolling-origin
backtest + `paired_origin_deltas` + permutation null; temperature calibration; `epss_at_publication` +
`build_epss_at_landmark` + the new date-pushdown; landmark/restart-clock infra; 8 model families;
VulnCheck/Shadowserver/ExploitDB connectors. The plan **adds labels, EPSS-trajectory + speed features,
distribution-handling, uncertainty, and rigor** — not redundant models.

---

## 15. Assumptions / Evidence / Hypotheses register

| Claim | Tag | Conf | Note |
|---|---|---|---|
| Labels+features > architecture for skill here | E | high | EPSS v1→v4 arc; ceiling memo |
| VulnCheck-KEV ~triples in-wild base | E | high | 4,969 on disk vs 1,623 CISA |
| Distribution has large t≈0 mass, non-stationary | E | high | 32%/24h; 745d→44d |
| EPSS-trajectory adds signal **beyond EPSS-at-pub** | H | med | circularity; needs X4 |
| EPSS features partly distill EPSS (circularity) | E | high | EPSS is an in-wild model |
| LLM-exploitability is a useful speed feature | H | med | 2025 AEG; anachronism risk; needs X5 |
| GNN won't beat AFT/Cox at this scale | H | med | no published TTW-GNN win; X10 |
| AFT (CatBoost/XGB) likely best tabular | E/A | med | verify CatBoost survival support |
| Informative censoring biases naive survival | A | high | needs sensitivity + competing-censoring |
| Social/dark-web adds lead-time | E | med | Sabottke; access-gated |

---

## 16. Reverse-engineering audit — 5 rounds (honest log)

- **R1 (data/features):** elevated `epss_history` from a buried row to the **cornerstone EPSS-trajectory
  family** (§4.2, §5.1) per user direction; tempered Shodan/Censys to cost-gated.
- **R2 (modeling/circularity):** added the **EPSS-circularity** challenge (§3.7) + EPSS-only baseline &
  marginal ablation (§5.1, §7, X3); specified ensemble **stacking** (not curve-averaging); marked CatBoost-AFT
  **[A, verify]**; added **patched-before-exploited competing-censoring** (§6.6).
- **R3 (eval/leakage):** specified **PR-AUC on the fully-observed subcohort**; flagged the **EPSS-v4
  comparability** caveat; identified **LLM-exploitability anachronism** (§5.2).
- **R4 (operational):** added **two operating points** (instant vs landmark, §1), a **≤24h head** (§7), a
  **concrete drift trigger** (>~10% Brier degradation, §8), **cold-start no-EPSS** handling, **LLM
  non-determinism caching**, and **commercial-feed license** risk (§4.1, §11).
- **R5 (honesty/scope):** replaced the placeholder §16 with this log; **downgraded over-optimistic confidences**
  (LLM/EPSS-trajectory → med); added the **program success/kill criterion** (§0).

## 17. Sources

EPSS v4 — Empirical Security 2025 (`research.empiricalsecurity.com/research/introducing-epss-version-4`);
FIRST EPSS. Collapsing window — Flashpoint "N-Day Trends"; CSA "Collapsing Exploit Window"; VulnCheck "State
of Exploitation"; Infosecurity (32% ≤24h). LLM exploit-gen — LLM-CVX (ACM AISec'25); ZeroDayBench; Patch-to-
PoC (arXiv 2025–26). Temporal-GNN fragility — arXiv 2509.25418. Dark-web/social — Sabottke et al. (USENIX'15);
Bitsight CTI. Expected Exploitability — Suciu et al., USENIX'22. Iannone TOSEM'24; Bozorgi KDD'10. (URLs in the
session research log; verify-before-trust per `check-for-better-methods`.)
