# Recovering Dropped 0-Day In-Wild Events (+51% usable dataset)

**Date:** 2026-06-21. Goal: increase the in-wild dataset size without new feeds
(external feeds blocked — VulnCheck exploit/ipintel indices return HTTP 402 on our
community token, Shadowserver unavailable, inthewild.io down). Reproduce:
`.venv/bin/python -u scripts/inwild_recover_negdur_eval.py` →
`artifacts/merged/inwild_recover_negdur.json`.

## The finding

The default modeling filter (`prepare_modeling_frame(recover_negative_duration=False)`)
**drops 1,585 of 4,690 in-wild events (34%)** — CVEs with a negative duration, i.e.
exploited at/before disclosure (0-days). Recovering them (floored to
`SAME_DAY_DURATION` = "exploited at disclosure") raises usable in-wild events
**3,105 → 4,690 (+51%)**. `rolling_origin_backtest` now takes
`recover_negative_duration` (default False; threaded into both train/test
`prepare_modeling_frame` calls).

## Measured impact (xgb, 15 rolling origins, label_set=in_wild)

| metric | drop | recover | paired Δ@90 (recover − drop) |
|---|---|---|---|
| usable test events | 1,310 | 2,303 (+76%) | — |
| AUC@90 (prevalence-independent) | 0.752 | 0.756 | +0.004 [−0.038, 0.045] — **n.s.** |
| PR-AUC@90 (prevalence-dependent) | 0.022 | 0.115 | **+0.093 [0.062, 0.123], 15/15** |
| recall@top-10%@90 | 0.423 | 0.445 | +0.022 [−0.038, 0.081] — n.s. |

## Honest interpretation

- **Discrimination is unchanged** (AUC flat, CI includes 0). The model did not get
  better at ranking; +51% training events did not move AUC — consistent with the
  documented data-limited ceiling.
- **The PR-AUC jump is mostly prevalence**, not skill: PR-AUC scales with the base
  rate, and recovery raised in-wild prevalence ~1.76×. It rose ~5× (more than
  prevalence) because recovered 0-days are high-profile/high-CVSS and rank easily —
  so part real, part mechanical. PR-AUC is **not comparable across prevalences**;
  cite AUC for model separation, PR-AUC only within a fixed cohort.
- **The real win is coverage/completeness:** we stop silently discarding a third of
  in-wild events — including the highest-priority *0-day-at-disclosure* class the
  model was previously blind to — and handle the fuller population with no loss of
  discrimination. That is the honest reason to adopt it, not a metric gain.

## Recommendation

Use `recover_negative_duration=True` for the **in-wild** label set (its negative
durations are genuine 0-days). Keep it **False for first-weaponization**, whose
negative durations are the PoC-date bulk-index *artifact* (see
`pipeline_characterization_2026-06.md`) — recovering those would inject noise.

## What this does NOT solve

The ceiling is still data-limited. Genuinely *new* in-wild timing data needs a
free-tier key for **GreyNoise** (observed in-wild exploitation, first-seen dates)
or **AlienVault OTX** — the only remaining accessible levers after the paid feeds.
