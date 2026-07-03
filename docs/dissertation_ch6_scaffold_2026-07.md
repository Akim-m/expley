# Chapter 6 writing scaffold — Deep & multi-state models

*2026-07-04. Writing scaffold (plan + verified numbers/figures/arguments), not prose. Sources:
`docs/deep_survival_headtohead_2026-06.md`, `docs/deephit_imbalance_fix_2026-06.md`,
`docs/pipeline_characterization_2026-06.md`, `docs/progress.md` §2026-06-21. Re-read artifacts
before final; numbers below are the living record.*

**Chapter thesis (the honest negative — a genuine contribution):** at this data scale, deep
survival models do **not** beat classical baselines on either discrimination or calibration; the
working tools are xgb-AFT (discrimination) and Cox (calibration + interpretable competing risks).
Report this as a *characterisation of where deep models win and lose*, not a failure to hide.

### 6.1 Models and why each
- Tier 3 rationale: DeepSurv (Cox-style deep hazard) and DeepHit (discrete-time competing risks)
  can learn non-linear hazards and non-proportional effects. AI-novelty framing (plan slide 7).
- Implementation notes: `deep.py` (DeepSurv), `deephit.py` (DeepHit), pycox + lazy torch/GPU.

### 6.2 Single-event head-to-head (discrimination + calibration)
- Setup: 212k train / 101k test, 45,527 test events; walk-forward; identical features.
- **Discrimination (time-dependent C):** xgb-AFT **0.614** [0.610,0.619] > DeepSurv **0.575** >
  Cox **0.562** [0.558,0.567]. **Calibration (integrated Brier ↓):** Cox **0.220** < xgb 0.240 <
  DeepSurv 0.287. → xgb wins discrimination, Cox wins calibration, **DeepSurv wins neither**.
- Interpretation: textbook tabular-survival behaviour (matches Burk 2026); publication-time
  structured features are low-dimensional/tabular — the regime where GBMs/linear models shine.
- Figure: `docs/figures/fig_two_heads.png`.

### 6.3 Competing-risks / multi-state
- Motivation (RQ2): cause-specific CIFs deviate from independence by **13–18% relative** for the
  rare causes (MSF/Nuclei/KEV/VulnCheck/ExploitDB) though ~0.75% for dominant PoC → a joint model
  is justified for rare transitions. Source: `pipeline_characterization_2026-06.md` §3.
- **Cause-specific Cox is the working model:** poc 0.563 [0.560,0.566] (matches single-event Cox —
  cross-check ✓), vulncheck_kev 0.749 (102 ev). Caveat: metasploit 0.889 / kev 0.834 are on
  36 / 6 test events — small-sample, not robust (flag explicitly).
- **DeepHit collapse → fix (a real methodological sub-result):** initial CIF@90 ≈ 3e-6 vs
  Aalen-Johansen truth ~0.19 (5 orders too small), concordance ~0.5. Root cause was time-bin
  **placement**, not loss `alpha` (falsified: raising alpha worsened it) nor bin count. Quantile
  discretization recovers CIF@90 ~0.17 (AJ truth ~0.10). Now default (`scheme="quantiles"`,
  `num_durations=50`). **Usable, still not better than Cox.** Source: `deephit_imbalance_fix_2026-06.md`.

### 6.4 Verdict and why (the mechanism, not just the numbers)
- Deep wins neither head at this scale because: (a) tabular low-dim features; (b) extreme class
  imbalance / censoring (52% censored, PoC 84% of events); (c) rare-event data ceiling (~396 in-wild).
- This satisfies the project's *minimum success* bar (plan slide 9: "even if deep only match
  baselines") and honestly does NOT meet the *stretch* goal — reported as a finding.

### 6.5 Limitations / threats
- Small-sample concordance for rare causes; discretization sensitivity in DeepHit; GPU-memory caps
  forced sampling (20k rows) in DeepSurv evaluation — note as an engineering constraint, not a result.

**Figures:** `fig_two_heads.png` (§6.2). **Tables:** single-event discrimination+Brier per model;
competing-risks per-cause C-index with event counts (so the small-n caveats are visible).
