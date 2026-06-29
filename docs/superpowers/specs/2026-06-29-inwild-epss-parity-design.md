# Design — In-wild target with EPSS parity, then label growth

**Date:** 2026-06-29
**Branch / worktree:** `inwild-epss-parity` (based at master 33662db)
**Status:** design (brainstorming output) → implementation plan next

## Problem

Our headline model targets **first-weaponization** — the earliest of public PoC /
Metasploit / Nuclei / KEV / 0-day — which is **~97% public PoC dates**. A public PoC is
*exploit tooling becoming available*, **not** a real-world attack. EPSS targets something
different: **P(exploited in the wild within 30 days)**, trained on in-the-wild
exploitation telemetry. So our headline numbers and EPSS are **not measuring the same
thing**, and any "beat EPSS" claim on the first-weaponization head is apples-to-oranges.

We already have a second label — **in-wild** = CISA KEV + Google Project Zero 0-day
(+ the merged VulnCheck deltas, ~4,690 events). That label **is** semantically what EPSS
predicts. This work makes it the primary target and measures against EPSS honestly.

## Goal

1. **Elevate the in-wild label to the PRIMARY target** for the EPSS comparison (without
   deleting first-weaponization, which stays as a larger-data supporting head).
2. **EPSS-parity evaluation harness** — identical target, estimand, and metric so the
   comparison is apples-to-apples:
   - target = `in_wild within H days of publication` (default **H = 30** to match EPSS's window),
   - estimand = a probability for that 30-day-from-publication outcome,
   - metric = top-k precision/recall (EPSS's deployment use) **and** AUC + PR-AUC with
     bootstrap CIs, walk-forward across time origins (the project's standard).
3. **Head-to-head, same target:** our structural in-wild model vs the **EPSS-at-publication**
   baseline; plus the **state-aware composite** (use EPSS where EPSS wins + the PoC→KEV
   escalation EPSS structurally cannot provide). Honest verdict: report where EPSS wins.
4. **Grow the in-wild label set** (the real lever to actually beat EPSS) via **GreyNoise**
   and the **VulnCheck KEV community** API, then re-run the parity harness.

## Non-goals (YAGNI)

- Not removing the first-weaponization head — it has the data volume and is a valid,
  separately-framed product (time-to-public-tooling).
- Not retraining/altering EPSS itself; EPSS-at-publication is a fixed baseline.
- **Not Shadowserver** — measured dead-end: region-locked, per-network registration,
  yields nothing usable here.
- Not honeypot ingestion this round.

## Phasing

- **Phase 1 — parity on the labels we have now ("beat EPSS, measured honestly").**
  Define the in-wild@H outcome, score EPSS-at-publication vs our in-wild model vs the
  composite, walk-forward, with CIs. Produces the head-to-head report + figure. This is
  buildable today and tells us exactly where we stand on EPSS's own target.
- **Phase 2 — grow the label set (GreyNoise + VulnCheck community), then re-run parity.**
  New fetch connectors → merge into in-wild events (using observation/first-seen DATES
  as event time) → rebuild → re-run the Phase-1 harness and quantify the lift from more
  labels. Exact endpoints/auth come from the API research now in flight (mirrors the
  existing `fetch/` connector pattern); design does not depend on the specific URLs.

## Components (reuse first, then add)

Reuse: `labels.py` (in-wild label build), `epss_at_publication.parquet` (EPSS arm),
`evaluate.py` / `proper_scoring.py` / `bootstrap_cindex_report` (metrics + CIs),
`backtest.py` (rolling origin), `triage.py` (the composite / PoC→KEV head),
`data/merged` (expanded in-wild events), `scripts/inwild_epss_ablation*.py` (prior art),
`scripts/build_report_figures.py` (figure style).

Add:
- **`in_wild_within_horizon(...)`** — a small, unit-tested helper that binarizes the
  in-wild survival labels into "event within H days of publication" with the existing
  right-censoring / negative-duration rules (a CVE censored before H is dropped from the
  positive/negative split, not counted as negative). One clear purpose; pure function.
- **`scripts/inwild_epss_parity.py`** — the head-to-head harness: EPSS-at-publication vs
  structural in-wild model vs composite, on the in-wild@H target, walk-forward, emitting
  top-k precision/recall + AUC + PR-AUC with bootstrap CIs to an artifact JSON + a figure.
- **Phase 2:** `fetch/greynoise.py` (+ extend `fetch/vulncheck.py` for the community KEV
  index), following the existing connector interface; merge layer wires the new dated
  events into the in-wild label.

## Leakage guards (non-negotiable)

- Features stay **publication-time-knowable** only (the existing firewall).
- The in-wild label uses **event dates**, never snapshot presence flags.
- GreyNoise / VulnCheck labels use **first-observed / date-added timestamps** as event
  time, with the same `negative_duration_flag` handling for dates before publication.
- EPSS as a *feature* stays as-is (the in-wild deployable config drops it); EPSS-at-publication
  is used here only as the **baseline arm**, not smuggled into our model.

## Success criteria

- A reproducible, walk-forward head-to-head on the **same target** that states, at matched
  operating points and with CIs, where we **beat / match / lose to** EPSS — and says so honestly.
- Phase 2: the growth in usable in-wild events is quantified, and the parity harness is
  re-run to show the effect of more labels on the EPSS gap.

## Risks

- **Label scarcity** is the known ceiling (~1% prevalence). AUC is the powered metric for
  model separation; PR-AUC / recall@k is the deployment metric — report both (project methodology note).
- **Access risk** for GreyNoise / VulnCheck free tiers (tokens, academic approval, rate
  limits) — being resolved by the research agent; Phase 2 is gated on a viable free path.
- **Temporal leakage via new label dates** — mitigated by the date-as-event-time rule above.

## Workflow

TDD per task (failing test → minimal impl → green → commit), tiny-fixture tests mirroring
real schemas, ≥5 reverse-engineering rounds after each major function/model (saved-memory
discipline), GPU-default for any heavy model, RAM/VRAM budget ≤6–8 GB / ≤7 GB.
