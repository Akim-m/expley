# MSRC In-Wild Source — Integrated, Measured Redundant

**Date:** 2026-06-21. User asked to add Microsoft MSRC exploitation data and train.
Done end-to-end; the honest result is that **MSRC is essentially fully redundant
with our existing CISA/VulnCheck KEV labels** and does not move the model.

## What was built

- `fetch/msrc.py` — `MsrcConnector`: pulls the free, public MSRC CVRF v3.0 monthly
  documents (no key), extracts CVEs flagged `Exploited:Yes` (Microsoft-confirmed
  in-the-wild) with the Patch-Tuesday `InitialReleaseDate`. **146** unique
  exploited CVEs (2017→2026). Parse logic unit-tested (no network).
- Wired into `EVENT_SOURCES`, `IN_WILD_SOURCES`, and `merge.MERGE_SPECS`
  (earliest-date-wins). MSRC only adds in-wild *labels*, not features — no feature
  rebuild needed.

## Measured value (the reason it stays, but doesn't matter yet)

Pre-flight probe vs existing in-wild labels (kev + vulncheck_kev + google_0day):

- 146–180 MSRC `Exploited:Yes` CVEs, **~97% already in our labels**;
- **6 genuinely new** in-wild CVEs across all years (all pre-2021);
- 17 overlapping CVEs get a ~7-day-earlier date.

## Trained model (in-wild xgb-AFT, 70/30 time split, published ≥ 2021, 0-days recovered)

| | with MSRC | without MSRC |
|---|---|---|
| in-wild events (cohort) | 2,785 | 2,785 — **Δ 0** |
| train / test | 127,108 / 55,338 | same |
| test events | 604 | 604 |
| **c-index (IPCW)** | 0.8424 [0.813, 0.871] | 0.8435 [0.815, 0.872] |
| integrated Brier | 0.0100 | 0.0102 |

**Δ c-index = −0.0011 (noise).** In the modeling cohort MSRC adds **0 net events**
(its 6 new CVEs are pre-2021; VulnCheck KEV covers every post-2021 one). Its only
effect was nudging 17 durations ~7 days earlier, which moved c-index by −0.001.

## Verdict

MSRC is correct, clean, confirmed data — and **redundant** with VulnCheck KEV for
this dataset. Kept wired as a standing source (it may catch *future* Microsoft
0-days before the KEV listing), but it does not raise the ceiling. This is the
third independent confirmation the ceiling is data-bound, not source-addable:
D3 hill-climb plateau, negative-duration recovery (AUC flat), and now MSRC (Δ 0).
The model itself is healthy on a proper 70/30 split (c-index 0.842 [0.81, 0.87]).
