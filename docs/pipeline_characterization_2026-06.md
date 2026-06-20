# Multi-State Weaponization Pipeline Characterization (RQ2)

**Date:** 2026-06-21. **Scope:** the professor's recommended "stronger thesis" — characterize the PoC→Metasploit→Nuclei→KEV weaponization pipeline as a multi-state process (`temporal_exploit_prediction.md` §Framing, §Directions RQ2). Merged build (`data/merged`, 359k corpus), snapshot 2026-03-14. Reproducible via `scripts/pipeline_cascade_characterization.py` + `scripts/pipeline_transition_models.py`; raw numbers in `artifacts/merged/pipeline_cascade.json` + `pipeline_transitions.json`. Every figure below survived a 7-round reverse-engineering audit (one round forced a correction — see §4).

## 1. The headline is a label-validity finding (caught before modeling)

The ordering analysis the professor mandates ("look at the data before you model it") surfaced a defect in the dominant label. **The git-mined PoC date conflates true PoC-publication time with the PoC aggregators' bulk back-fill/indexing dates for older CVEs.** Evidence:

- Three single dates carry enormous PoC counts — **2022-02-10 (15,011 CVEs), 2022-02-19 (10,983), 2022-02-12 (7,739)** — plus 2024-12-26 (4,206) and 2019-12-08 (1,151). These are nomi-sec/Trickest re-index events, not real PoC-publication clusters.
- Spot-checks: EternalBlue (CVE-2017-0144) and Heartbleed (CVE-2014-0160) both carry the PoC date **2019-12-08** — years after their Metasploit modules. Log4Shell (CVE-2021-44228, recent) is correct: PoC 2021-12-10, MSF 2021-12-13.

**Consequence:** time-to-PoC is right-biased for older CVEs, and since PoC is 97% of first-weaponization events, this is a primary suspect for the weak first-weaponization discrimination (xgb AUC ≈ 0.60). **Mitigation adopted:** restrict pipeline timing analyses to the **clean recent cohort (CVE published ≥ 2021)**, where the aggregators index in near-real-time. Older CVEs' PoC dates should be treated as unreliable (a known missing-data pattern, per the doc's framing of `epss_at_publication` NaN).

## 2. Does the pipeline cascade? Yes — once the artifact is controlled

`cascade_order_stats` (% where stage *a* precedes stage *b* among CVEs observed in both):

| transition | n co-observed | PoC-before-next (all CVEs) | (published ≥ 2022) |
|---|---|---|---|
| PoC → Metasploit | 2,547 | 31.1% | **81.0%** |
| Metasploit → Nuclei | 501 | 59.7% | — |
| Nuclei → KEV | 421 | 63.7% | — |

PoC-before-MSF rises **monotonically** with publication year — 56.7% (≥2018) → 66.9% (≥2020) → 76.1% (≥2021) → 81.0% (≥2022) — while n *shrinks* (1,331→725), confirming the inversion is publication-age-driven (the artifact), not a sample-size effect. **On the clean cohort the pipeline cascades in the expected order** PoC→MSF→Nuclei→KEV.

## 3. Are the transitions independent? Mostly — but not for the rare causes

Aalen-Johansen competing-risks CIF vs the independent-KM product (`cif_vs_independent`), deviation at 180 days, **relative to each cause's CIF**:

| cause | CIF@180 | absolute inflation | **relative** |
|---|---|---|---|
| PoC (dominant) | 0.2160 | 1.6e-3 | **0.75%** |
| Metasploit | 0.0017 | 3.1e-4 | **17.9%** |
| Nuclei | 0.0022 | 3.3e-4 | **15.2%** |
| KEV | 0.0001 | 9.3e-6 | **13.6%** |
| VulnCheck-KEV | 0.0010 | 1.8e-4 | **17.3%** |
| ExploitDB | 0.0106 | 1.4e-3 | **12.8%** |

The *absolute* dependence is small everywhere (~1e-3), so a naive read is "competing risks are independent." **That read is wrong for the rare causes:** relative to their small CIFs, the competing-risks correction is **13–18%** for Metasploit / Nuclei / KEV / VulnCheck / ExploitDB — only the dominant PoC cause is genuinely independence-like (0.75%). **Implication:** modeling the rare tooling/in-wild transitions with a *joint* competing-risks model (Aalen-Johansen, cause-specific Cox, DeepHit) rather than independent per-cause survival is materially justified — which directly motivates the Phase-2 competing-risks deep head-to-head.

## 4. What predicts each transition? (recent cohort, time-based split, held-out)

`build_transition_labels(from="poc", to=X, competing_sources=…)` — clock origin = PoC date, competing tooling/in-wild sources censor cause-specifically; Cox + XGBoost-AFT; held-out 70/30 time-split `transition_cindex`:

| transition | events (recent / all) | median lag | Cox c-index | XGBoost-AFT c-index |
|---|---|---|---|---|
| PoC → Metasploit | 510 / 640 | 58 d | 0.592 | 0.526 |
| PoC → Nuclei | 1,588 / 2,049 | 114 d | 0.753 | **0.794** |
| PoC → KEV | 293 / 648 | 67 d | 0.819 [0.775, 0.864] | **0.869 [0.839, 0.897]** |

(PoC→KEV CIs are 300-resample bootstraps on the 83 test events.) **The transitions are heterogeneous:**

- **PoC → Metasploit is near-chance** (xgb 0.53, cox 0.59). Whether Rapid7 weaponizes a PoC'd CVE into an MSF module is *not* predictable from publication-time metadata — it is driven by pentester demand / exploit reliability the dataset doesn't carry.
- **PoC → Nuclei is well-predicted** (xgb 0.79) and slowest (median 114 d) — detection-template coverage tracks structured features (product family, weakness type).
- **PoC → KEV — the in-wild endpoint — is the most predictable** conditional on a PoC (xgb 0.87, bootstrap-stable, decisively above chance), and fast (median 67 d). This is the operationally valuable signal: *given a CVE already has a public PoC, publication-time metadata ranks which ones reach confirmed in-wild exploitation well.*

## 5. Caveats (required for the viva)

- **PoC dominance.** 97% of first-weaponization events are PoC dates; the §1 artifact means a large fraction of those are unreliable for older CVEs. The recent-cohort restriction is the defense; it shrinks event counts (esp. PoC→KEV: 648→293).
- **Informative censoring.** "No signal observed by snapshot" is not "no weaponization"; standard survival methods assume non-informative censoring, which is violated here (niche/unmonitored CVEs are over-represented in the censored set).
- **Small in-wild-endpoint samples.** PoC→KEV rests on 293 events / 83 test; the c-index is bootstrap-stable but single-split — report the CI and event count, never the bare point estimate. (Lesson carried from the 2026-06-21 landmark correction: at low event rates, prefer the powered metric + CI.)

## 6. Implications for the remaining work

1. **Phase 2 deep-at-scale head-to-head should run on the clean recent cohort** (or report the artifact's effect), else it inherits the PoC-date noise.
2. **The competing-risks/DeepHit model is justified** by §3 (material dependence for the rare causes) — not just a viva box-tick.
3. **The deployable story** is the conditional one: *PoC-present → time-to-KEV* (xgb 0.87) is far stronger than the unconditional first-weaponization model (0.60), because it sidesteps the noisy PoC-origin artifact and targets the operationally meaningful escalation.
