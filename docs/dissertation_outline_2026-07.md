# Dissertation outline & content map — ECS8056

*Draft scaffold, 2026-07-04. For review. Maps completed+verified work → chapters; marks
what is ready to write vs pending. Numbers cited here are LIVE from artifacts/docs — do
not hand-copy into prose without a live re-read (see each source).*

**Title (working):** *Temporal Exploit Prediction: Survival Models for the Timing of Public
Weaponisation of CVEs.* Submission 9 Sep 2026 (W13).

**One-sentence thesis:** A leakage-safe survival-analysis layer over a multi-source CVE
timeline predicts *when* a CVE accumulates public exploitation capability, complements EPSS
(which predicts in-the-wild probability over a fixed 30-day window), and — reported honestly
— shows that at this data scale classical models match or beat deep survival, and that the
binding constraint on the in-the-wild task is label scarcity, not model capacity.

| # | Chapter | Purpose | Source material (ready → draftable now) | Status |
|---|---------|---------|------------------------------------------|--------|
| 1 | Introduction | Timing problem; disclosure→weaponisation; decision framing | Plan slides 1–2; `temporal_exploit_prediction.md` §Framing | Ready |
| 2 | Background & related work | EPSS, survival analysis, censoring; rare-event exploit-prediction lit | `literature_rare_event_exploit_prediction.md`, `research_competitive_methods_2026-06.md` | Ready |
| 3 | Data | 9 sources, corpus, label composition, **label-source sweep incl. HackerOne** | `modeling_methodology.md` §11, `label_completeness_2026-06.md`, `inwild_label_source_sweep_2026-06.md`, `hackerone_epss_reconciliation_2026-07.md` | Ready |
| 4 | Methodology | Target, clock, censoring, negative durations, **leakage controls**, splits | `modeling_methodology.md` §1–8, `architecture_flow.md` | Ready |
| 5 | Baselines & discrimination | KM, Cox, RSF, xgb-AFT; C-index/Brier/calibration | `deep_survival_headtohead_2026-06.md`, `calibration_by_horizon_2026-06.md`, progress.md §2026-06-21 | Ready |
| 6 | Deep & multi-state models | DeepSurv/DeepHit, competing risks; **honest "classical wins at this scale"** | `deep_survival_headtohead_2026-06.md`, `deephit_imbalance_fix_2026-06.md`, `pipeline_characterization_2026-06.md` | Ready |
| 7 | EPSS reconciliation | ML-vs-ML: where we agree/disagree with EPSS; **HackerOne blind-spot case study** | `inwild_epss_parity_2026-06.md`, `hackerone_epss_reconciliation_2026-07.md` | Ready |
| 8 | Causal & pre-disclosure dynamics | Wormable acceleration (HR~1.3), patch-race selection bias | `causal_and_patch_race_2026-06.md` | Ready |
| 9 | Discussion: threats to validity | PoC dominance, informative censoring, label ceiling, in-wild scarcity | Plan slides 6/8; `modeling_methodology.md` §9; label-source docs | Ready |
| 10 | Conclusion & future work | Contributions; the real lever is more/better in-wild labels | progress.md, memory `inwild-ceiling-is-data-limited` | Ready |

## Headline results to feature (all measured, cite live)

- **Discrimination (single-event in-wild):** xgb-AFT ≈ 0.61 > DeepSurv ≈ 0.58 > Cox ≈ 0.56;
  Cox best calibration. Deep does not win either axis at this scale (`deep_survival_headtohead`).
- **EPSS parity (in-wild target, deployable no-EPSS structural model):** structural beats EPSS on
  ranking **+0.100 AUC@30** [0.055, 0.145] / +0.134 AUC@90; **PR-AUC tied**; EPSS wins recall@top-1%.
  Baseline must be the RAW EPSS percentile, not an AFT-wrapped fit (that collapses to ~chance).
- **HackerOne reconciliation (new, this session):** coordinated-disclosure membership carries a
  **9× in-wild lift concentrated in EPSS's bottom decile** (37 exploited CVEs EPSS cold-started
  low — e.g. Apache Struts CVE-2017-5638), clustered in CWE-22/-502/-94. **Ablation: adds
  −0.0018 AUC@30 [−0.005,+0.002] over the structural model** → real vs EPSS, redundant with our
  features. A quantified "where EPSS is blind" narrative, not a feature.
- **Competing risks:** cause-specific Cox is the working multi-state model; DeepHit collapsed then
  was fixed (quantile time-bins) but does not beat Cox.

## What is NOT claimed (honesty guardrails — keep these explicit in the prose)

- Not in-the-wild *attack* prediction: ~97% of events are public-PoC dates; in-wild proxy is
  ~93% VulnCheck-KEV catalog membership with ~175d median administrative lag, not exploitation onset.
- Not an EPSS competitor; a complement with an explicit reconciliation.
- Deep-learning stretch goal (beat baselines on rare states) NOT met — data ceiling (~396 in-wild
  events), and this is reported as a finding, not hidden.

## Pending before submission (not blockers to drafting)

- Final figure pass (reuse `scripts/build_report_figures.py`).
- Front matter (abstract, acknowledgements, declaration) — institution template.
- Proof-read numbers with a live artifact re-read (the report generators read live; mirror that).
