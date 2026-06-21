# Beat-EPSS Attempt — Gated Hill-Climb (D3)

**Date:** 2026-06-21. Reproduce: `scripts/beat_epss_hillclimb.py` → `artifacts/merged/beat_epss_hillclimb.json`. autoresearch-style greedy forward selection over leakage-safe feature groups; accept gate = significant paired per-origin delta (95% CI excludes 0) on a 15-origin rolling backtest; hard plateau stop; final config shuffle-null-checked.

## Verdict

**A leakage-safe feature config significantly beat EPSS-only** at recall@top-10%.

- metric: recall_at_top@30d, top fraction 0.1
- EPSS-only recall@top-10%@30d: **0.10308185594735007**
- final config (epss, cvss) recall: **0.1304465024169573**
- final vs EPSS paired delta: **0.02736464646960723** (95% CI [0.013156711724088435, 0.041572581215126025])
- accepted groups (in order): ['cvss']
- shuffle-null recall (sanity, must be ≪ real): 0.10143048169824449

## Trial log

| round | added group | mean Δ recall | 95% CI | decision |
|---|---|---|---|---|
| 1 | cvss | 0.02736464646960723 | [0.013156711724088435, 0.041572581215126025] | **ACCEPT** |
| 1 | severity | 0.011228352316695039 | [-0.002283718331002566, 0.024740422964392644] | — |
| 1 | misc | 0.020263565982320316 | [0.006911728058068179, 0.03361540390657245] | significant |
| 1 | cpe | 0.005635043231781315 | [-0.008765886760986934, 0.02003597322454956] | — |
| 1 | cwe | 0.022613272236285988 | [0.008468942497056473, 0.0367576019755155] | significant |
| 1 | incentive | 0.0236602105886339 | [0.005570191073718936, 0.04175023010354886] | significant |
| 1 | attack | 0.01299500008207048 | [0.0015785198262200997, 0.02441148033792086] | significant |
| 2 | severity | 0.0019215644495978465 | [-0.003342204292126987, 0.00718533319132268] | — |
| 2 | misc | 0.0021455429025002823 | [-0.003472846669529189, 0.0077639324745297535] | — |
| 2 | cpe | 0.0006385480640673809 | [-0.0050381278228833785, 0.00631522395101814] | — |
| 2 | cwe | 0.003244286914118902 | [-0.005082326487490837, 0.01157090031572864] | — |
| 2 | incentive | -0.001792985212288592 | [-0.0070814789106087035, 0.003495508486031519] | — |
| 2 | attack | 0.0059420019886443805 | [-0.0011294918432875611, 0.013013495820576322] | — |

## Interpretation

The hill-climb can only add whole publication-time-safe feature groups, so it cannot climb via leakage; and it accepts a group only when the per-origin gain is statistically significant, so it cannot chase tiny-event noise. The accepted groups are a genuine, reproducible improvement over EPSS-only.