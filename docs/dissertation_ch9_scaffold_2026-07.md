# Chapter 9 writing scaffold — Threats to validity

*2026-07-04. Writing scaffold (plan + the honest caveats to state explicitly), not prose. Sources:
plan slides 6 & 8, `docs/modeling_methodology.md` §9, `docs/causal_and_patch_race_2026-06.md`,
`docs/inwild_epss_parity_2026-06.md`, the label-source + disclosure-platform sweep docs. This is the
chapter that makes the dissertation *credible* — surface every limitation unprompted.*

**Chapter thesis:** the results are valid *for what they measure* — the accumulation of public
exploitation capability and a publication-anchored known-exploited proxy — and this chapter states
precisely where they do NOT generalise, quantifying each threat rather than gesturing at it.

### 9.1 Construct validity — what the label actually is
- **PoC dominance:** ~97% of events are public-PoC dates → the target is *public exploitation
  capability*, not in-the-wild attack. Do not overclaim.
- **In-wild proxy:** the in-wild label is ~93% VulnCheck-KEV catalog membership; `date_added` is an
  administrative catalog-add date (median lag ~175 d; only ~22% within the 30-day horizon), not
  exploitation onset. The EPSS head-to-head is fair (both arms see the identical proxy) but "same
  target as EPSS" is the soft part, not the number.

### 9.2 Internal validity — leakage
- **Temporal leakage (NVD back-edits):** descriptions are edited post-event with "actively
  exploited"/"KEV" phrasing → masked via `text_safety`; residual bias quantified vs archived text.
- **Snapshot-time feature leakage:** every feature frozen as-of a point in time; default set excludes
  `vrs_presence` and snapshot EPSS. The reconciliation/HackerOne flag is publication-safe by
  construction (`disclosed_at ≤ published`).
- **Walk-forward discipline:** time-based split committed to file before modelling; permutation-null
  no-look-ahead check in the backtest.

### 9.3 Informative censoring
- Whether a CVE is censored may correlate with risk (a CVE that never gets a public PoC differs
  systematically). Treated as a threat explicitly; sensitivity analyses run. State residual risk.

### 9.4 Selection bias
- **Bug-bounty attention (this session):** which CVEs appear on HackerOne/ZDI/Patchstack is not
  random (well-resourced vendors, web/app stack) — so any "these get exploited less/more" comparison
  is confounded. Flagged where the HackerOne blind-spot lens is used (Ch7).
- **Patch-race selection bias:** the patch-vs-exploit race is selection-biased (only CVEs that reach
  both states are observed); quantified in `causal_and_patch_race_2026-06.md`. 28.6%/35.5% exploited
  on/before disclosure figures carry this caveat.

### 9.5 External validity — the data ceiling
- ~396 usable in-wild events cap discrimination/calibration on the in-wild task; deep models don't
  beat classical (Ch6) because of this, not model capacity. **Measured, not assumed:** the in-wild
  label space is saturated (label-source sweep) and disclosure platforms add 0 in-wild labels
  (disclosure-platform sweep) — the only unexploited crack is Patchstack's paid WordPress `is_exploited`.
- Statistical-power note: ~9.5 events-per-variable regime → shrinkage + reduced features; the sparse
  one-hot blocks earn little prospectively (`inwild_feature_prune`).

### 9.6 Model-assumption threats
- Cox PH non-proportional hazards → flexible deep models that don't need the assumption (though they
  don't win here); report PH diagnostics.

### 9.7 What would change the conclusions
- More/earlier in-wild labels (VulnCheck onset dates, GreyNoise prospective telemetry, or Patchstack
  WordPress) — the honest "future work that moves the ceiling", not a fancier model.

**No new figures required; reference the sweep verdict tables and the label-composition table (Ch3).**
