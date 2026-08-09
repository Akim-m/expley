# Scope Expansion for Temporal Exploit Prediction — Executed & Evidence-Backed

> This document answers the scope-expansion proposal (`scope_increase_temporal_exploit_prediction.pdf`)
> with the *executed* version: each strand grounded in the project's real artifacts and, for external
> claims, in web-verified primary sources (not the proposal's restated figures). Two proposed strands
> were deliberately excluded after triage: **§4.2** (OSV.dev patch competing-risks — inherits the
> project's already-measured commit-date *selection bias*) and **§5.2** (named-feed telemetry —
> credential-blocked this cycle). Cross-references point to the dissertation chapters
> (`docs/dissertation_ch{3,5,6,7,9}_scaffold_2026-07.md`).
>
> **Status legend:** ✅ built/measured · 📝 framing of existing results.

---

## 2. Reframing the core question — *time to public weaponization* 📝

The binding constraint is label scarcity. At snapshot 2026-03-14 the event composition across 338,015
CVEs is: **160,873 PoC**, 2,246 Metasploit, 1,693 Nuclei, **531 CISA-KEV**, **133 Google-0-day**, and
172,539 right-censored (165,476 observed, ~49%). PoC dates are **~97%** of all events; the only true
in-the-wild signals are KEV + Google-0-day, **664 combined** and only **~396 usable** after dropping
event-before-publication cases (3,255 CVEs carry negative durations, min −3,505 days). The corpus
in-the-wild base rate is **0.46%** (CISA-KEV-only; a broader KEV/VulnCheck/0-day/MSRC definition gives
1.38%). So per-CVE in-wild prediction is data-limited, not model-limited. The honest headline is
therefore **"predict *when public exploitation capability appears*"**, not "when a vulnerability is
exploited in the wild." Concretely, the primary target is **time from CVE publication to the first
public weaponization signal** (PoC, Metasploit, Nuclei, or catalogue membership); in-the-wild
exploitation is a deliberately-underpowered secondary analysis reported with wide intervals.

This is a *complement* to EPSS, not a competitor: EPSS scores a fixed 30-day in-the-wild-exploitation
probability [1] (now on model v5, 2026-06; it reports PR-AUC, not ROC-AUC, given the severe class
imbalance), whereas this project models the **multi-horizon timing** of the ordered
PoC → tooling → catalogue cascade at cold start from publication-time covariates only. See
`docs/modeling_methodology.md` §9/§11 and dissertation Ch.3.

## 3. Methodological scope expansion

### 3.1 Leakage-safe survival analysis under rare events 📝

The pipeline enforces a **leakage firewall**: default features are restricted to values knowable at
publication time, and each feature family carries a `feature_provenance()` row with an explicit
`leakage_status`. The firewall excludes three temporally-contaminated families that a naive pipeline
would happily use:

- **NVD description text** — NVD back-edits descriptions *after* exploitation with phrases like
  "exploited in the wild" / "CISA" / "KEV", so description-derived features leak the label.
- **Snapshot-time presence flags** (`vrs_presence`) — recorded at snapshot, not publication.
- **Snapshot-time EPSS** — inherently post-publication; only the first EPSS reading *after*
  publication is admissible.

Only publication-time-knowable values are safe: CVSS, CWE, CPE vendors/products, ATT&CK from the
stable MITRE chain. `feature_provenance()` emits one row per feature family with its source column and
`leakage_status = "publication_time_safe"`, written to `feature_provenance.csv` on every build — an
auditable trail, not a convention.

Methodologically the project operates in the rare-event survival regime, and the reusable
contribution ("leakage-safe survival analysis on rare-event security data") is a set of concrete
fixes with measured effect. lifelines' ridge scales as `n·penalizer·‖β‖²/2` while the partial-
likelihood information scales with the *event* count, so a fixed penalizer over-shrinks by ~`n/d_events`
— **~24×** on the in-wild target (975 train events among 234k rows) — compressing the calibration
slope **~10×**. The fix scales the penalizer by the event rate; and when a near-zero ridge let a
quasi-separated covariate **invert the ranking (c-index 0.19)**, tenfold penalizer escalation runs
until convergence. Covariates are admitted only with **≥5 positive events** (`stable()`). So-penalized
Cox remains robust and competitive against deep survival architectures on this tabular data.

### 3.2 Interval-censored PoC modelling — *built, with an honest reframe* ✅

**Motivation.** PoC "event dates" are contaminated by repository-indexing batches: the recorded date
is when a PoC was *indexed*, an upper bound on when it actually existed. The proposal expected this to
bias survival estimates and interval-censoring to correct it.

**What was built.** A discrete-time (person-period) interval-censored survival model
(`src/temporal_exploit/interval_censored.py`, `scripts/build_interval_censored.py`, 12 tests): the
timeline is binned on horizon-aligned edges {7, 30, 90, 180, 365, 730}, each PoC event is assigned to
its *containing bin* (grouped interval-censoring), and a discrete-time logistic hazard
`P(event in bin k | x) = σ(β·x + γ_k)` is fit on standardized publication-time features with raw
per-bin baselines. Converged, CPU-only, 4.5 GB peak (within budget).

**The honest finding (this is the contribution).** The proposal's premise is *wrong*, and the data
proves it:

- PoC records cluster **severely in calendar time** — 31 of 2,009 distinct dates hold **50%** of the
  160,313 PoC records; the single busiest day holds **9.4%**. (Confirms the indexing-batch pathology.)
- But they **smear out in duration space** — it takes **239** distinct durations to reach 50%
  (~8× flatter) — because `published` varies per CVE, so calendar clustering does *not* translate to
  duration clustering.
- Therefore batch indexing **does not bias the aggregate time-to-PoC survival curve.** The original
  "bias exhibit" (grouped-life-table vs naive-KM) was structurally blind — the two are the same
  estimator, ~0 by construction (max |Δ| = 3.9e-4 at bin edges *and* on a fine 15-day grid). It was
  replaced with the correct instrument: **calendar-vs-duration concentration** + an
  **indexing-lag sensitivity** bound.
- The **residual indexing-lag bias is bounded**: assuming every PoC truly predated its indexed date by
  90 days moves S(90) only from **0.82 → 0.79**.

This is a first-class **negative result** (feeds §6) and a concrete instance of the telemetry-bias
theme (§5.1): a widely-assumed data pathology, *measured* and shown not to propagate to the modelling
target. The discrete-time model stands as the robust deliverable; its EPSS-free discrimination is
**c-index 0.5824** (vs 0.5835 with EPSS accidentally included — EPSS added ~nothing, reinforcing the
project's structural-beats-EPSS finding, and per the standing *no-EPSS-in-training* directive the
model excludes it). Cross-ref dissertation Ch.6.

## 4. Causal characterization and the patch-vs-exploit race

### 4.1 Exploit-before-disclosure and the patch race — *measured* ✅

The causal module (`src/temporal_exploit/causal.py` → `artifacts/merged/causal_characterization.json`;
adjusted Cox + stabilized IPW + overlap/positivity diagnostics + VanderWeele–Ding E-values) turns the
"under what conditions does exploitation beat disclosure/patch?" question into estimated hazard
ratios. On the abundant first-weaponization target (n = **313,847**; **147,048** events; event rate
0.47):

| Treatment | Crude HR | Adjusted HR | IPW HR | E-value | Verdict |
|---|---|---|---|---|---|
| **Wormable** (AV:N/PR:N/UI:N/AC:L) | 1.71 | **1.29** (p≈0) | 1.41 | 1.68 | real acceleration |
| **Unauth-network, high-impact** | 1.56 | **1.24** (p≈0) | 1.38 | 1.58 | accelerates |
| **ATT&CK-chain-mapped** | 1.09 | **0.97** | 1.07 | 1.16 | confounded null — framework correctly refuses |

Wormable vulnerabilities are causally weaponized faster, and the effect survives every specification
(HR never crosses 1); the ATT&CK-chain null is a case where the causal machinery *correctly* declines
an estimate the naive log-rank tactic study reported as significant.

**The patch race is bimodal, and patch-date observability is itself the selector**
(`artifacts/merged/patch_race.json`): in the commit-dated OSS cohort (n = **11,227**), the fix lands a
**median 14 days *before*** the CVE is published and only **0.5%** are weaponized before patch — the
race is pre-decided, defenders win *if they patch*, and PoCs trail the fix by a median **155 days**.
The time-varying "patches enable n-day exploits" Cox is underpowered here (HR 0.63, wide CI
[0.45, 0.89]). The dangerous exploit-before-patch cases (0-days, advisory-only) are *systematically
excluded* from any commit-date model — which is exactly why the proposal's §4.2 (OSV.dev patch
competing-risks) was dropped: it would inherit this selection bias. The unbiased signal is the
corpus-wide pre-disclosure weaponization rate, computable with no fetch: **28.6%** of
first-weaponizations and **35.5%** of in-the-wild exploitations occur **on or before** CVE
publication — a figure that independently **matches VulnCheck's reported 28.96%** of full-year-2025
KEVs exploited on/before publication [2], an external validation of the label pipeline. (VulnCheck's
1H-2025 slice runs higher at 32.1%, up from 23.6% in 2024; Mandiant's time-to-exploit series
independently corroborates the "weeks → days" collapse, from ~63 days in 2018–19 to ~5 days in 2023
[3].) See `docs/causal_and_patch_race_2026-06.md`.

## 5. Threat-intelligence & telemetry bias as first-class objects

### 5.1 KEV / catalogue-style signals 📝

CISA's KEV is the central "known-exploited" label, but it is incomplete, source-skewed, and *lagged* —
facts the project treats as *modelled objects*, not nuisances, and quantifies from its own data:

- **Source dominance.** Of 1,310 kept in-wild test events, **~93% (~1,220) are VulnCheck-KEV**, only
  90 CISA-KEV, and 0 Google-0-day (all 132 0-days are exploited pre-publication → negative-duration →
  dropped). VulnCheck tracks **~3,672** exploited CVEs to CISA's **~1,345** (~80% more) and its
  evidence dates run a median **~197 days earlier** than CISA's catalogue-add.
- **Catalogue-add lag.** "Added to KEV" is *not* "exploited": the median gap from publication to KEV
  add is **175 days** (only **~22%** land inside the 30-day horizon); CISA's median lag is **+329d**,
  VulnCheck's **+107d**, and **>1/3** of VulnCheck events are added more than a year post-publication.
- **Launch backfill.** **246/975 (25%)** of in-wild training events are dated exactly on the KEV
  catalogue launch (2021-11-03) — an artefact the training clock must exclude, not learn from.

External analyses corroborate the coverage gap: Perkal (via Cyentia's *Prioritization to Prediction*
v9) puts it at **~94%** of exploited CVEs absent from KEV [4], and a 2026 recomputation over 17,000+
tracked exploited CVEs lands in the same place — KEV covers **≤8.7%** (~91% absent) [5]. GreyNoise's own
KEV evaluation reports tags for only **~20%** of KEV entries, with telemetry openly skewed toward
initial-access, remote, internet-exposed targets [6]. Treating KEV *additions* as catalogue events
rather than exploitation timestamps — and quantifying the source/lag skew above — is the
"threat-intelligence bias" strand. Cross-ref dissertation Ch.3/Ch.9.

## 6. Honest negative results as a scoped deliverable 📝

The project treats negative results as first-class, documented so future work does not retest them
blindly. Formalized as a catalog — each *hypothesis → experiment → outcome → diagnosis*:

- **Mixture-cure model.** *Hypothesis:* a logistic-incidence + Weibull-latency cure model yields honest
  absolute in-wild probabilities (positive IPA) where Cox/XGB sit at ≈0. *Single split (cutoff
  2024-01-01):* it wins — IPA **+0.0036 / +0.0050 / +0.0057** @30/90/180d with matched discrimination
  (c-index **0.832** vs Cox 0.837). *Prospective backtest:* it **reverses** — under rolling-origin
  walk-forward the cure model becomes actively harmful (**IPA@180 → −0.27**). *Diagnosis:* a cure
  fraction is only identifiable with a Kaplan–Meier plateau; the ~99.5%-censored in-wild target is
  *administratively* censored, not a cured population (Li–Taylor–Sy 2001). → single-split wins are a
  backtest trap.
- **LambdaRank objective.** Ranking loss (`rank:ndcg`) vs XGB-AFT: AUC **−0.126 [−0.202, −0.050]** @30d,
  **−0.164 [−0.215, −0.113]** @90d (win-fraction 0.00). *Diagnosis:* binary within-horizon labels
  discard the survival-time signal and ~0.1% positives starve pair sampling → adoption rejected, ships
  opt-in only.
- **Temperature / temporal recalibration.** Monotone rescaling preserves ranking perfectly (AUC@90
  bit-identical across all 15 origins) but **degrades mean calibration** (mean IPA@90 **+0.00110 →
  +0.00033**). *Diagnosis:* on event-starved origins any recalibration ≤ baseline.
- **Interval-censoring "bias correction" (§3.2, new).** The assumed batch-date survival bias does not
  exist at the aggregate level (calendar clustering smears in duration space); the naive metric was
  structurally blind. (See §3.2.)

Cross-ref dissertation Ch.6; source docs `docs/research_model_building_pitfalls_2026-06.md`,
`docs/improvement_log_2026-07-02.md`, `docs/audit_2026-06-12.md`, and the ablation artifacts
(`a2_lambdarank_ab.json`, `inwild_temporal_recal.json`).

## 8. Conclusion

The scope expansion converts unavoidable data limitations into explicit, researchable dimensions:
temporal reframing to weaponization, leakage-safe rare-event survival, a *new* interval-censored PoC
model that turned a wrong premise into an honest measured finding, causal characterization of the
patch/exploit race, and bias-aware treatment of threat-intelligence feeds. Every internal figure is
traceable to a committed artifact; every external figure is web-verified.

---

### Internal sources
`artifacts/merged/{causal_characterization,patch_race,interval_censored}.json`; `artifacts/{a2_lambdarank_ab,inwild_temporal_recal,inwild_floor_ablation}.json`; `docs/{modeling_methodology,causal_and_patch_race_2026-06,research_model_building_pitfalls_2026-06,audit_2026-06-12,inwild_epss_parity_2026-06,inwild_label_source_sweep_2026-06,hackerone_epss_reconciliation_2026-07}.md`; `src/temporal_exploit/{interval_censored,causal,features,modeling}.py`.

### External references (web-verified 2026-08-09)
1. Jacobs, J. et al. "Exploit Prediction Scoring System (EPSS)." *Digital Threats: Research and Practice*, ACM, 2021 — https://dl.acm.org/doi/10.1145/3436242. Model/version data: FIRST.org EPSS — https://www.first.org/epss/data (current model v5, 2026-06-15; PR-AUC-reported). *Note: the legacy "ROC-AUC 0.838" is EPSS v1 on a 12-month window; current EPSS reports PR-AUC under class imbalance.*
2. VulnCheck. "State of Exploitation — 1H-2025." 2025 — https://www.vulncheck.com/blog/state-of-exploitation-1h-2025. (Full-year-2025: 28.96% of KEVs exploited on/before publication; 1H-2025: 32.1%, up from 23.6% in 2024.)
3. Mandiant / Google Cloud. "Time-to-Exploit Trends 2023" (2024) — https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023 — and "M-Trends 2026" (2026). (Mean TTE ~63d (2018–19) → ~5d (2023).)
4. Perkal, Y. (Rezilion). "CISA KEV — A Balanced Perspective." Medium — https://medium.com/@yotamperkal/cisa-kev-a-balanced-perspective-ff3856e69ba9, citing Cyentia Institute, *Prioritization to Prediction* v9 (2022). (~94% of exploited CVEs absent from KEV; secondhand to the P2P v9 primary.)
5. Empirical Security. "The KEV Paradox." 2026 — https://research.empiricalsecurity.com/research/the-kev-paradox. (Independent recomputation over 17,000+ tracked exploited CVEs: KEV covers ≤8.7%.)
6. Rudis, B. (GreyNoise). "Evaluating the CISA KEV." GreyNoise, 2022-06-15 — https://www.greynoise.io/blog/evaluating-cisa-kev. (Tags for ~20% of KEV; telemetry focused on initial-access/remote exploits; pattern persists in GreyNoise's 2025 Mass Internet Exploitation Report.)
