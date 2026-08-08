# Design: Scope Expansion for Temporal Exploit Prediction (2026-08-09)

> Origin: `scope_increase_temporal_exploit_prediction.pdf` — a 7-strand scope-expansion
> proposal written from the project report + data-gap audit. Feasibility-triaged against the
> live codebase before design (most strands are already built; two were dropped by the user).
> Standing constraints throughout: **≤6–8 GB system RAM, ≤7 GB VRAM** (`memory-budget-constraint`),
> TDD, `uv` env, push-after-commit, leakage firewall (publication-time features only).

## Scope decision

The proposal's seven strands, triaged against the repo:

| # | Strand | Repo status | In this spec |
|---|--------|-------------|--------------|
| §2 | Reframe → "time to public weaponization"; complement EPSS | Already the framing (CLAUDE.md caveat, report §9/§11) | ✅ writeup |
| §3.1 | Leakage-safe survival as a methodological contribution | Built (firewall, `feature_provenance`) | ✅ writeup |
| §3.2 | **Interval-censored PoC modelling** | **Not implemented** | ✅ **new build (flagship)** |
| §4.1 | Exploit-before-disclosure as its own question | Built (`causal.py`, `patch_race_analysis.py`) | ✅ writeup/elevation |
| §4.2 | Competing risks w/ patch dates (OSV.dev) | ~~Collides with known selection-bias dead-end~~ | ❌ **dropped by user** |
| §5.1 | KEV/catalogue bias as first-class object | Quantified in data-gap audit | ✅ writeup/elevation |
| §5.2 | Named-feed exploitation (GreyNoise/VulnCheck) | ~~Credential-blocked this session~~ | ❌ **dropped by user** |
| §6 | Anti-patterns catalog (cure/LambdaRank/recalibration negatives) | Results documented, scattered | ✅ consolidation |
| §7 | Triage CLI + dashboard | CLI built; dashboard net-new | ✅ new artifact (static HTML) |

**Confirmed scope: §2, §3.1, §3.2, §4.1, §5.1, §6, §7.** §4.2/§5.2 explicitly excluded.

The work decomposes into three buckets: **(A)** the one genuinely-new model (§3.2), **(B)** a new
surfacing artifact (§7), **(C)** a research-narrative restructure consuming existing results
(§2/3.1/4.1/5.1/6). Each is independently testable/reviewable. Sequencing **A → B → C**: A produces
the flagship result and exhibits that C's §3.2 subsection needs; §4.1/§5.1/§6 can proceed alongside A.

---

## Bucket A — §3.2 interval-censored PoC model (NEW; flagship)

**Motivation (from the audit).** PoC "event dates" are contaminated by repository-indexing batches:
half of all PoC records fall on 36 of 2,191 distinct dates, and median publication→PoC gaps far
exceed plausible exploit-development latency. The recorded date is therefore an **upper bound** on
when the PoC existed, not its true appearance time. Treating it as an exact event time makes
weaponization look like it arrives in sudden batches and biases every downstream survival estimate.

**New module:** `src/temporal_exploit/interval_censored.py` — single purpose, mirrors existing
module conventions (tz-aware UTC, ndarray-safe, no writes to handover parquets). Data source:
`per_signal_labels.parquet` for the PoC signal (`published` → `poc_first_seen`), joined to the
publication-time feature matrix (`build_publication_features`, leakage-safe).

**Two components.**

1. **Grouped interval-censored NPMLE bias exhibit** — the nonparametric interval-censored survival
   curve computed with each PoC assigned to its **containing time-bin** `(loₖ, hiₖ]` (grouped
   interval-censoring — this is what destroys within-bin batch-date exactness), compared against the
   naive exact-date KM. *Why grouped, not `[published, poc_first_seen]`:* in duration terms the latter
   is `[0, dᵢ]` for every CVE (nested-from-zero / all-left-censored), whose NPMLE collapses back to
   approximately the naive estimate and does **not** correct the batch bias. Turnbull's NPMLE
   specializes to the actuarial **life-table** estimator when every interval endpoint lies on a shared
   grid (the bins), so the exhibit is a life-table-vs-naive-KM comparison — no fragile EM.
   Output: the divergence between the two curves quantified (median-time shift; max/area curve
   distance at the horizon grid) and a figure. This is the "here is the bias" result.
   *Negative-duration PoCs* (`poc_first_seen < published`, where the duration is < 0) are excluded from
   the survival fit exactly as the existing baselines already reject negative durations — reported as a
   count, not silently dropped, and carried into §4.1's exploit-before-disclosure framing instead.

2. **Discrete-time hazard covariate model** — person-period expansion: one row per `(cve, interval)`
   until the interval containing the event (or censoring). Bins are **horizon-aligned**:
   `(0,7], (7,30], (30,90], (90,180], (180,365], (365,730], (730,∞)` so the project's existing
   `(7,30,90,180)` evaluation horizons fall on bin edges. Per-interval discrete hazard
   `P(event in bin k | X) = logistic(β·X + γ_k)` (logistic baseline; GBM/XGB variant optional and
   subject to the VRAM cap). The PoC event is assigned to the **interval containing** `poc_first_seen`,
   which is exactly interval-censoring at bin resolution — batch dates within a bin no longer
   masquerade as distinct timing. Survival `S(t|x) = Π_{k: edge_k ≤ t} (1 − hazard_k(x))`; horizon
   probabilities `1 − S(τ|x)` at τ ∈ {7,30,90,180}.

**Interface (matches what `evaluate`/`backtest` already dispatch on):** `feature_cols_`,
`risk_scores(X)` = `P(event by max horizon)` (monotone ranking score), `survival_at(X, horizons)`
= `S(τ|x)` above. Provides a `fit_discrete_time(...)` entry point and a `turnbull_curve(...)` helper.

**Leakage safety:** features come from `build_publication_features` only; add a `feature_provenance()`
row if any new derived feature is introduced (none expected — interval construction changes the
*label/likelihood*, not the covariates).

**Success criteria (measurable):**
- Turnbull vs naive-KM divergence reported as a concrete number (median-time shift in days + curve
  distance) — the bias is quantified, not asserted.
- Discrete-time model emits `(7,30,90,180)`-day probabilities with a c-index reported head-to-head
  against the existing exact-date first-weaponization baseline (`xgb`), on the locked
  cutoff-2024-01-01 time split.
- The interval-aware treatment demonstrably changes the survival curve and/or ranking in a
  documented direction (predicted, then verified — see below).

**Prediction to verify (falsifiable):** because batch dates cluster PoC observations *later* than the
true (unknown) appearance time, the naive exact-date KM should sit **below** (more pessimistic
survival = faster apparent weaponization near batch dates) — i.e., the Turnbull curve should show
weaponization is *not* as sharply time-clustered as the exact-date treatment implies. If the two
curves are indistinguishable (divergence ≈ 0), the batch pathology does not materially bias survival
and §3.2's premise is wrong — that null is itself a reportable finding.

**Budget:** person-period logistic on ~360k CVEs × ≤7 bins is a tabular GLM — well under 6–8 GB RAM,
CPU-only by default (GBM/XGB variant only if it stays under the 7 GB VRAM cap).

**Testing (TDD, tiny fixtures per repo convention):**
- Discrete-time hazard recovers a known per-bin hazard on synthetic person-period data.
- Turnbull curve diverges from naive KM when events are artificially batched, and coincides when
  they are not (guards the bias-detection logic both ways).
- `risk_scores`/`survival_at` are monotone and bounded in [0,1]; horizons align to bin edges.
- Leakage guard: model refuses / provenance flags any non-publication-time feature.

---

## Bucket B — §7 dashboard (NEW artifact; static HTML)

**Decision:** a **self-contained static HTML report**, not a live server — no external deps, trivially
under the RAM budget, consistent with the repo's `scripts → artifacts/` convention. (Can be promoted
to a publishable Artifact later if a shareable link is wanted.)

**New script:** `scripts/build_dashboard.py` → `artifacts/dashboard.html` (gitignored `artifacts/`).
Consumes existing surfaces — `triage.build_triage_table` / `triage.operating_points`,
`effort_metrics` (PR-AUC CIs, recall-by-fraction), `decision_curve.net_benefit_table` — plus the new
§3.2 exhibits (Turnbull-vs-naive figure, interval-model horizon curves).

**Contents:** (a) calibrated lead-time table (median days of head-start before later-stage signals);
(b) effort-vs-coverage / net-benefit curve; (c) the §3.2 bias exhibit + interval-model horizon
probabilities. Everything inlined (CSS/JS/SVG or embedded PNGs) so the file is portable.

**Success:** one command produces a portable `dashboard.html` rendering all three sections from live
artifacts with no invented numbers. Smoke test asserts the file builds and contains the expected
section anchors from a tiny fixture artifact set.

---

## Bucket C — research-narrative restructure (writeup; consumes existing results)

Extends the in-flight `docs(p6)` dissertation chapters. **No new numbers are invented** — each strand
consumes real artifacts; external citations are web-verified per the standing "check-for-better-methods"
preference (refresh EPSS AUC≈0.83, CSA collapsing-window ≈32% pre-disclosure, Perkal ≈94%-not-in-KEV,
GreyNoise KEV-bias) rather than trusting the PDF's numbers.

- **§2** — thesis framing: "time to public weaponization" as the primary target; in-wild as a
  deliberately-underpowered secondary with wide CIs; positioned as a state-aware temporal *complement*
  to EPSS (multi-horizon timing + ordered PoC→tooling→catalogue cascade), not a competitor.
- **§3.1** — "leakage-safe survival analysis under rare events" as a reusable methodological toolbox
  (firewall + provenance + EPV discipline), generalized beyond this one model.
- **§4.1** — "exploit-before-disclosure & collapsing windows": elevate the existing causal/patch-race
  results (`causal.py`, `patch_race_analysis.py`; the 28.6% first-weaponization / 35.5% in-wild
  pre-disclosure figures, externally matched to VulnCheck's 28.96%) into a standalone research question.
- **§5.1** — "KEV / catalogue-style signals as a first-class bias object": vendor/weakness skew,
  catalogue-lag, and the "additions are catalogue events, not exploitation timestamps" framing.
- **§6** — "anti-patterns for rare-event survival modelling": consolidate the documented negatives
  (mixture-cure wins-a-split-fails-prospective, LambdaRank harms AUC in sparse regimes, temperature
  recalibration degrades mean performance while preserving ranking) into one
  hypothesis → experiment → outcome → diagnosis catalog so future work does not retest them blindly.

**Success:** each strand is a written, citation-grounded section wired to real artifacts; every
external claim carries a verified source; no result contradicts a live number in `artifacts/`.

---

## Cross-cutting

- **Reproduce/verify (`process-self-correction-rules`):** `time -v` heavy steps to file; reproduce
  manifest flags on rebuilds; run the full `pytest` gate (FutureWarning-as-error) before each commit;
  ≥5 reverse-engineering loops after the §3.2 model lands (`reverse-engineer-after-runs`).
- **RE via ≤2 subagents × 3–5 loops** for the adversarial check of the flagship model.
- **Out of scope (explicit):** OSV.dev / patch competing-risks (§4.2), new telemetry feeds
  (§5.2), any live server for §7, and any modeling that ingests EPSS into training (standing directive).
