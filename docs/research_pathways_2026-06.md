# Methods, pathways & functions to change the flow — deep research (2026-06-19)

> Six parallel literature sweeps, **60+ papers (2022–2026)**, asking: *what other
> methods, pathways, or functions could be substituted to get better results?*
> The sweeps independently converge on one meta-finding and a ranked set of
> concrete flow-changes. Companion to `docs/literature_rare_event_exploit_prediction.md`
> (which settled the model-class question: penalized Cox is the in-wild backbone).

## Meta-finding (all six sweeps agree)

**The in-wild ceiling is data-limited (396 events), not model-limited — so the
biggest "better result" is more/earlier label data, and the second-biggest is
fixing the *calibration* output (IPA≈0), not the ranking (AUC≈0.82 is already
good).** A neutral 2025 benchmark quantifies this exactly: penalized Cox is
"remarkably robust at small sample sizes," and boosting needs ≥600 events,
transformers ≥1,200, to beat it (Rossi et al., "Beyond Cox Models,"
arXiv:2504.17568, *Comput. Biol. Med.* 2025). At 396 events we are firmly in
Cox's territory for ranking. The leverage is elsewhere.

---

## Pathway 1 — More/earlier in-wild LABEL data (highest leverage)

The ceiling is event count; this raises it directly.

- **VulnCheck KEV — free community API** (`vulncheck.com/kev`; "State of
  Exploitation 2026"). **~173 % larger than CISA KEV, ~27 days earlier on
  average**; ~29 % of 2025 KEVs exploited on/before CVE publication day. Already
  wired in our connector (`fetch/vulncheck.py`) — the blocker was "needs token,"
  and the research surfaced that the **community tier is free**. Use
  *first-reported-evidence date*, not catalog-add date.
- **Shadowserver honeypot feeds** (free, daily, timestamped, CVE-tagged;
  VulnCheck's named #1 earliest in-the-wild reporter 2024) — another in-wild
  label source.
- **GitHub PoC feeds as an as-of-date covariate** (nomi-sec/trickest; repo
  `created_at`): VulnCheck 2024 found 70 % of KEVs had a PoC *before* exploitation
  — a leading indicator. Filter malware/fake PoC repos (arXiv:2210.08374).
- Dead ends at the free tier: GreyNoise CVE history (paid; already an EPSS
  partner so largely inside EPSS-at-publication), dark-web/forum corpora (gone),
  Twitter/X (API lockdown).

**Verdict:** VulnCheck KEV (free) + Shadowserver could **2–4× the true in-wild
events with earlier dates** — far more impactful than any model change. Roadmap
#1. (Implementation gated on the connector run / a free token.)

## Pathway 2 — Borrow strength: transfer / multi-task / frailty (abundant→rare)

Inject the ~100k first-weaponization events into the ~396 in-wild model.

- **Transfer survival, pretrain→fine-tune** — Zhao et al., "Tackling Small-Sample
  Survival via Transfer Learning," arXiv:2501.12421 (2025): pretrain on 27k
  source, fine-tune on as few as 50 target; DeepSurv C-index 0.772→0.804. The
  literal template (caveat: their source/target are the *same* outcome; ours
  differ — harder).
- **Penalized-Cox transfer / multi-task** — `survtrans` (`coxtrans`/`coxmtl`,
  CRAN); Li, Shen, Ning, "Accommodating Time-Varying Heterogeneity under the Cox
  Model: A Transfer Learning Approach," *JASA* 2023; CoxTL (medRxiv 2025). Same
  family as our champion, one λ controls how hard in-wild leans on
  first-weaponization. Lowest-risk borrow.
- **Shared-frailty illness-death (semi-competing risks, penalized)** — Reeder,
  Liu, Haneuse, *Biometrics* 2023 (arXiv:2202.00618). Three transition hazards
  (PoC→tooling→in-wild) tied by a shared frailty + fused penalty; the frailty is
  estimable from the *abundant* transitions, so it survives the 396-event
  problem. **Best structural fit to our cascade.**
- **Deep Survival Machines** (Nagpal et al., `auton-survival`) and **MENSA**
  (Cao et al., arXiv:2409.06525, trajectory likelihood encoding PoC→in-wild
  order) — the neural arms; defer (396 positives in one head overfits).
- **Guardrail (mandatory if multi-task):** ForkMerge (Jiang et al., NeurIPS 2023,
  arXiv:2301.12618) — negative transfer is the default failure at n=396.
- **Honesty test first:** meta-analytic surrogacy (RMST individual-level
  surrogacy) — measure PoC→in-wild surrogacy *before* trusting transfer; if low,
  no architecture helps.

**Verdict:** the most promising *model* pathway. Cheapest feasible version
(implemented below): **stacked transfer** — use the abundant first-weaponization
Cox's risk score as a single covariate in the in-wild Cox.

## Pathway 3 — Positive-Unlabeled / label-noise reframe (censored ≠ negative)

The deepest reframe: "not-yet-weaponized" is *unlabeled*, not negative, and the
noise grows with recency (Expected Exploitability's core finding).

- **Foundations:** Menon et al., ICML 2015 (PU = a special case of label noise);
  Elkan & Noto, KDD 2008; nnPU (Kiryo et al., NeurIPS 2017); class-prior
  estimation BBE+CVIR (Garg et al., NeurIPS 2021).
- **PU-meets-survival:** Toyabe et al., "Positive-Unlabelled Survival Data
  Analysis," arXiv:2011.13161 — our exact data structure; naive survival is
  "severely biased."
- **Mixture-cure as a PU/incidence model:** Sy & Taylor, *Biometrics* 2000;
  Kuk & Chen, *Biometrika* 1992 (logistic "ever-weaponizable" × Cox latency, EM).
  *We tried this and it was an identifiability dead-end* — see Pathway 6.
- **Time-dependent labeling propensity (our exact hardest case):** Nagaraj et al.,
  "Learning under Temporal Label Noise," ICLR 2025 (arXiv:2402.04398); Bekker et
  al., SAR-PU, ECML-PKDD 2019 — set propensity `e(x)=f(CVE age)` so recently
  published CVEs (whose absent labels are most likely false negatives) are
  up-weighted. Laptop-trivial (reweight + EM).

**Verdict:** the time-dependent-propensity reweight is a cheap, principled fix
for *the* core defect; roadmap candidate. The full mixture-cure is a dead-end
(Pathway 6).

## Pathway 4 — Better OUTPUTS: calibration, proper scoring, uncertainty (functions, not a model)

Targets the real weak spot (IPA≈0) without swapping the model.

- **Our IPA metric may itself be the problem:** the Integrated Survival Brier
  Score (basis of IPA) is **not strictly proper** (Sonabend et al.,
  arXiv:2212.05260, 2022). Report **RCLL** (right-censored log-likelihood,
  strictly proper) and RISBS instead — IPA≈0 at <1 % base rate may be partly a
  *non-proper-metric* artifact (Yanagisawa, "Proper Scoring Rules for Survival,"
  ICML 2023). **Cheapest high-value change.**
- **Recalibrate cheaply:** "Good Rankings, Wrong Probabilities" (Ghawami,
  arXiv:2604.04239, 2026) documents our exact pathology and shows
  Platt/temperature recalibration improves calibration *without* hurting
  discrimination — and **warns isotonic overfits with few events** (which we
  independently found). Temperature scaling = 1 parameter, immune to the n=396
  overfit that killed our isotonic recalibration.
- **Competing-risks calibration:** Alberge et al., arXiv:2602.00194 (2026) —
  proper per-cause CIF calibration (`hazardous` lineage).
- **Uncertainty without a new model:** bootstrap-ensemble the Cox for predictive
  bands (Lillelund et al., IEEE BHI 2023 idea). Conformalized survival
  (Candès/Lei/Ren, *JRSS-B* 2023; resampling version Qin et al., *Biometrics*
  2025) gives distribution-free intervals **but degrades under heavy censoring** —
  gate on per-fold empirical coverage before trusting at our ~99.5 % censoring.
- **Utility:** decision-curve / net-benefit (Vickers et al., 2023) — at 0.47 %
  prevalence a 0.82-AUC ranker can have near-zero net benefit; DCA exposes it.

**Verdict:** RCLL metric + temperature recalibration are the two cheapest,
highest-ROI changes and target exactly our weak spot. **Prototyped below.**

## Pathway 5 — Latest model classes worth a bake-off (low expectation at 396)

- **Cheap untried gap:** XGBoost native `survival:cox` (`tree_method="hist"`) —
  histogram-based, *no* O(n²) blowup that killed sksurv's Cox-loss GBM (Barnwal
  et al., *JCGS* 2022 is the AFT sibling we did try). One-line objective swap.
- **CatBoost** native `Cox`/`SurvivalAft` (interval-censoring) — best shot at a
  tuned GBM on ~70 mixed features; deploy on the *abundant* target (Rossi's
  ≥600-event rule).
- **The one genuinely-new few-shot class:** TabPFN-for-survival — SurvivalPFN
  (arXiv:2605.15488, 2026), "Survival In-Context" (arXiv:2603.29475), "Tabular
  Foundation Models Can Do Survival Analysis" (arXiv:2601.22259). Prior-fitted
  nets have a *structural* few-shot advantage and run in ~one forward pass. The
  only realistic swing at beating Cox on the rare target — verify event-count
  floor + RAM first.
- Skip at our scale: SODEN (neural-ODE, slow), Survival-SVM (no calibrated
  curve), SurvTRACE/transformers (need ≥1,200 events).
- **Infra:** SurvHive (arXiv:2502.02223) unifies lifelines/sksurv/pycox behind
  one API for the bake-off; "Stop Chasing the C-index" (arXiv:2506.02075) backs
  reporting calibration over AUC.

**Verdict:** XGBoost `survival:cox` is a near-free gap to close on the abundant
target; SurvivalPFN is the one defensible rare-target swing. Roadmap, not now
(both need infra/data checks).

## Pathway 6 — Formally close the cure-model question

We deprecated the mixture-cure model empirically (it lost the backtest) and
theoretically (no KM plateau ⇒ non-identifiable). The frontier offers a *rigorous
close*, not a revival:

- **Sufficient-follow-up tests** — Xie, Escobar-Bach, Van Keilegom, *Biometrical
  Journal* 2024 (arXiv:2309.00868); Maller et al. 2024. A formal hypothesis test
  that follow-up is insufficient to identify a cure fraction — converts our
  empirical dead-end into a **citable statistical statement**. Cheap; do it.
- **Promotion-time cure with an identifiability layer** — Medina-Olivares et al.,
  *IEEE TNNLS* 2024 (arXiv:2305.11575): less plateau-dependent, but at 99.5 %
  administrative censoring "long-term incidence" is still extrapolation — honest
  only as a *bounded* susceptibility, never a calibrated cure rate.

**Verdict:** run the sufficient-follow-up test to rigorously retire cure; don't
revive it.

---

## Ranked actionable roadmap

| # | Pathway | Leverage | Effort | Status |
|---|---|---|---|---|
| 1 | **VulnCheck KEV (free) + Shadowserver** — 2–4× in-wild labels, earlier dates | **highest** (raises the ceiling) | low–med (fetch/token) | roadmap — the real fix |
| 2 | **Temperature recalibration** — target IPA≈0 | high (the weak spot) | low | **prototyped — negative** ✗ |
| 3 | **Stacked transfer** — first-weaponization risk as an in-wild covariate | med–high | low–med | **prototyped — negative** ✗ |
| 4 | **Sufficient-follow-up test** — rigorously close the cure question | med (rigor) | low | roadmap |

### Prototype results (2026-06-19) — both confirm the data-limited ceiling

- **Stacked transfer** (`scripts/inwild_stacked_transfer.py`, via the new
  `backtest.augment_fn` hook): inject the abundant first-weaponization Cox's
  per-CVE risk score as one in-wild covariate, point-in-time per origin.
  **Δ ≈ 0** (AUC@90 −0.0004, recall +0.0027, IPA −0.0001 — all ≪ sd 0.069). The
  source risk is a non-linear combination of features the in-wild Cox *already*
  has, so it carries no new information. Confirms the literature: the 396-event
  ceiling is also a *transfer* ceiling. A richer transfer (shared-frailty over
  the actual PoC **events**, not a feature — Pathway 2) is the remaining untried
  variant.
- **Temperature recalibration** (`calibration.py`, `temperature=True`): 1-param
  S^exp(a), learned out-of-sample by k-fold cross-fitting, monotone in S so
  **ranking is provably unchanged** (AUC@90 identical 0.8173 = 0.8173). But it
  **worsened the mean IPA** (@90 −0.003 → −0.092) while leaving the **median
  unchanged** — i.e. on event-starved origins the cross-fit learns a *harmful*
  temperature from ~7 events. A `min_events=40` guard cuts the @90 harm ~80 %
  (−0.092 → −0.020) but @180 stays bad (−0.091): even ≥40-event origins have
  unstable 180-day calibration (17.7 % subcohort drop). Same rare-event
  recalibration fragility the isotonic attempt showed. **Recommendation:
  recalibration OFF for in-wild.** RCLL (the proper-metric half of this pathway)
  remains worth adding as a *reporting* change — it may show IPA≈0 is partly a
  non-proper-metric artifact — but it does not change the model.

**Net:** neither flow-change beats baseline penalized Cox; IPA≈0 is the
data-limited reality. The achievable win is Pathway 1 (more label data).
| 5 | Shared-frailty illness-death / penalized-Cox transfer (survtrans) | med–high | med (R/custom EM) | roadmap |
| 6 | Time-dependent PU propensity reweight (SAR-PU, `e(x)=f(age)`) | med | low–med | roadmap |
| 7 | XGBoost `survival:cox` (hist) on the abundant target; SurvivalPFN on rare | low–med | med | roadmap (bake-off) |
| 8 | Decision-curve / net-benefit eval | med (honesty) | low | roadmap |

**Bottom line:** no model swap beats penalized Cox for *ranking* at 396 events —
the field's own benchmarks say so. The achievable wins are (a) **more label data**
(VulnCheck/Shadowserver — raises the ceiling), (b) **calibration + proper metrics**
(the IPA≈0 weak spot), and (c) **borrowing the abundant first-weaponization signal**
into the rare target (stacked transfer / shared frailty). We prototype (b) and a
cheap form of (c) now, formally close cure, and stage the data-enrichment as the
highest-leverage next step.
