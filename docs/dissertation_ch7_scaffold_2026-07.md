# Chapter 7 writing scaffold — EPSS reconciliation (ML-vs-ML)

*2026-07-04. A **writing scaffold**, not prose: section plan + the exact verified numbers,
figures, and arguments to write FROM. Deliberately not ghost-written — keep the dissertation
prose your own. Every number cites a live artifact/doc; re-read before final to avoid drift.*

**Chapter thesis:** the timing model is not an EPSS competitor but a complement; a systematic
ML-vs-ML reconciliation shows *where* the two agree/disagree and *why*, and a concrete
coordinated-disclosure lens (HackerOne) names a population EPSS systematically under-ranks.

### 7.1 Motivation — why reconcile, not compete
- EPSS: one probability per CVE, next-30-day in-the-wild, refreshed daily. This model: a full
  survival curve, multiple horizons/states. Different questions → reconciliation, not a race.
- Deliverable framing from the project plan (slides 4 & 7): the reconciliation is an *explicit
  result*, not an afterthought.

### 7.2 Same-target head-to-head (the fair comparison)
- Source: `docs/inwild_epss_parity_2026-06.md`, `scripts/inwild_epss_parity.py`,
  `artifacts/inwild_epss_parity.json`; figure `docs/figures/fig_epss_parity.png`.
- Setup to describe: identical walk-forward origins, identical in-wild target, both arms see the
  same rows. **Two correct arms:** (a) our structural model with NO EPSS (deployable); (b) the
  RAW EPSS percentile ranked directly (`score_col` passthrough).
- **The measurement bug to report honestly:** wrapping EPSS (a calibrated score) in an xgb-AFT fit
  collapses it to ~chance (0.501); ranking the raw percentile gives 0.695. This *corrects* earlier
  over-stated margins — a methodological contribution in its own right.
- **Result:** structural beats EPSS on ranking **+0.100 AUC@30** [0.055, 0.145] / **+0.134 AUC@90**;
  **PR-AUC tied**; **EPSS wins recall@top-1%**. Mechanism: in-wild positives sit at median
  publication-time EPSS percentile **0.168** — EPSS is dynamic and hasn't reacted at t=0.
- Honesty caveat (must state): the "in-wild" label is ~93% VulnCheck-KEV catalog membership;
  `date_added` is an administrative catalog-add date (median lag ~175 d), not exploitation onset.
  Fair comparison (both arms see the identical proxy); the "same target as EPSS" name is the soft part.

### 7.3 Where they disagree — the HackerOne blind-spot case study
- Source: `docs/hackerone_epss_reconciliation_2026-07.md`; figure
  `docs/figures/fig_hackerone_epss_blindspot.png`; `scripts/hackerone_epss_reconciliation.py`.
- Argument: coordinated-disclosure (HackerOne bug-bounty) membership is **not** an in-wild label
  source (1,725 CVE-tagged reports, only 68 overlap KEV, all pre-labelled → 0 new labels) — but it
  **marks** in-wild CVEs EPSS under-ranks: **9× in-wild lift in EPSS's bottom decile** (37 exploited
  CVEs, e.g. Apache Struts CVE-2017-5638; clustered in CWE-22/-502/-94).
- Close the loop with the ablation (don't oversell): a leakage-safe H1 flag adds **−0.0018 AUC@30**
  [−0.005, +0.002] over the structural model (RE-verified real null via oracle/noise controls).
  → EPSS misses these; a model *with the structural features does not*. HackerOne is a narrative
  lens on EPSS's cold-start blind spot, not free lift. This is the honest punchline.

### 7.4 What the disagreement means for practice
- EPSS is strongest at the very top (recall@top-1%) — use it for the daily triage cut. The timing
  model adds the *curve* (7/30/90/180) and catches serious-RCE cold-starts EPSS ranks low.
- Tie to the defender-interpretation work (`docs/defender_interpretation_2026-06.md`,
  `scripts/defender_score.py`, `docs/figures/fig_operating_points.png`).

### 7.5 Limitations
- Proxy target (catalog-add timing), label scarcity (~396 in-wild events — the ceiling), selection
  bias in which CVEs get bug-bounty attention. Forward-reference Chapter 9 (threats to validity).

**Figures to place:** `fig_epss_parity.png` (§7.2), `fig_hackerone_epss_blindspot.png` (§7.3),
`fig_operating_points.png` (§7.4).
**Tables to build:** parity per-arm AUC@30/90 + PR-AUC + recall@top-k; H1 overlap/ablation summary.
