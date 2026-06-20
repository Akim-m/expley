# Defender-Facing Interpretation + a State-Aware Triage Score

**Date:** 2026-06-21. **The required deliverable** from `temporal_exploit_prediction.md` §"What success could look like": *"An interpretation of results that connects back to vulnerability-management practice — what would a defender do differently knowing these predictions?"* Plus a **model improvement**: a state-aware triage score that uses the best tool per weaponization state. Reproduce: `scripts/defender_score.py` → `artifacts/merged/defender_operating_points.json`. Aggressive RE: ≥11 rounds (one ruled out a bug behind a surprising result; one bootstrapped the small-sample headline).

## The honest operating-point finding (what works, what doesn't)

A defender triaging at **publication time** ranks CVEs and patches the top slice. We measured operating points (recall / precision / lead-time at the top 1/5/10%) on the clean recent cohort (published ≥ 2021, 70/30 time split).

### State 1 — at publication: **EPSS is the best top-k ranker; our survival model is not**

| top-k | model (xgb structural+EPSS) | EPSS-at-publication only |
|---|---|---|
| top 1% | precision 0.278 | **0.468** |
| top 5% | 0.276 | **0.393** |
| top 10% | 0.302 | **0.347** |

(base rate of first-weaponization within 30 d = 0.264.) **EPSS-only wins at every operating point.** RE confirmed this is *not* a bug and *not* a sign error: the full model actually has the higher **overall c-index** (xgb 0.585, cox 0.584 vs EPSS-only 0.560), but at the **sharp top** EPSS — a purpose-built calibrated probability — concentrates true positives better than a concordance-optimised survival model. The survival models' advantage lives in the broad middle of the ranking, not the top decile where triage operates. **Defender takeaway: for publication-time PoC-tooling triage, use EPSS.** Our model does not beat it there, and we say so.

### State 2 — once a public PoC exists: **the PoC→KEV model is the real value-add**

| top-k of PoC'd CVEs | recall of eventual KEV | precision |
|---|---|---|
| top 1% | 0.15 | 0.036 |
| top 5% | 0.39 | 0.019 |
| **top 10%** | **0.52 [0.40, 0.65]** | 0.012 |

(KEV-within-90d base rate = 0.0024; 66 KEV events; recall CI is a 1000-resample bootstrap.) Watching the **top 10% of PoC'd CVEs catches ~half of those that reach CISA-KEV in-wild exploitation**, with a **median ~42-day lead** before the KEV listing. RE: no leakage (no KEV/snapshot features), and an adversarial risk-shuffle drops recall to 0.14 (≈ random) — so the 0.52 is real signal, not base-rate inflation. **This is exactly what EPSS-at-publication cannot give:** it is conditional on the observable PoC-present state and yields a *time-to-in-wild* ranking, not a static 30-day probability.

## The model improvement — a state-aware escalating triage score

A single static model is dominated (by EPSS at the top in state 1; data-limited in-wild). The deployable improvement is to **switch tools as the CVE moves through the weaponization state machine**:

1. **State PUBLISHED (no PoC yet):** triage by **EPSS** (best top-k ranker), with two cheap, RE-verified context modifiers from this project:
   - **ATT&CK tactic (RQ3):** CVEs whose techniques map to **Defense Evasion / Persistence** weaponize fastest (median time-to-PoC ~35–46 d vs ~63–72 d for Credential/Initial Access; log-rank p≈1e-102, survives shuffle + de-overlap) → bump their priority.
   - **time-to-PoC incidence (RQ1):** publication features rank *which* CVEs get a PoC (~0.59) but barely *when* (timing-only c-index 0.534) — so treat "will it get a PoC" as the signal, not a precise ETA.
2. **State POC-PRESENT (a public PoC appears):** **escalate** — run the **PoC→KEV** model. The top decile captures ~52% of eventual in-wild exploitation ~weeks ahead. This is the project's deployable contribution.

This composite beats EPSS-alone (it adds the state-2 escalation EPSS can't provide) and beats any single survival model (it uses EPSS where EPSS wins). It is a *complement* to EPSS along the weaponization pipeline — precisely the role the framing doc prescribes, not an EPSS replacement.

## What a defender does differently (the bottom line)

- **At disclosure:** keep using EPSS for the first-cut patch ranking — our survival layer does not beat it there, and pretending otherwise would be dishonest.
- **Add the pipeline context we *can* defensibly provide:** flag Defense-Evasion/Persistence-tactic CVEs as fast-weaponizers; treat the time-to-PoC model as a "will-it-get-a-PoC" incidence signal.
- **The moment a public PoC lands, escalate:** the PoC→KEV model flags the ~10% of PoC'd CVEs that carry ~half the eventual in-wild risk, with a median ~6-week head start — the window to pre-emptively patch/mitigate before CISA-KEV listing. **This is the operational decision the model changes.**

## Honest limits (required framing)

- **Not in-wild at publication.** The strong signal is *conditional on a PoC*; at t=0 the in-wild target is data-limited (`inwild-ceiling-is-data-limited`). The system characterises the *pipeline to* in-wild, not silent in-wild exploitation no one has catalogued.
- **Precision is prevalence-bounded.** KEV is ~0.24% of PoC'd CVEs in 90 d, so absolute precision is low even at recall 0.52 — the value is *recall with lead-time* for a watch-list, not a high-precision alarm.
- **PoC-date artifact + informative censoring** apply throughout (see `pipeline_characterization_2026-06.md`); the clean recent-cohort restriction is the mitigation.
- **ATT&CK coverage ~24%**, and the tactic mapping is a curated primary-tactic assignment — directional, not a per-technique ground truth.
