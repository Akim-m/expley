# In-wild EPSS parity: do we beat EPSS on the same target? (2026-06)

**TL;DR.** On the **same target EPSS predicts** — in-the-wild exploitation (CISA KEV +
Google 0-day + VulnCheck), within 30/90 days of publication — our publication-time
structural model **beats EPSS on ranking by a modest, significant margin** (+0.100 AUC@30
[0.055, 0.145]; +0.134 AUC@90 [0.089, 0.178]), is **statistically tied on precision**
(PR-AUC), and **loses the very sharp top** (EPSS wins recall@top-1%). It is a complement /
modest improvement, **not** a blowout. Source: `scripts/inwild_epss_parity.py` →
`artifacts/inwild_epss_parity.json` (15 walk-forward origins, 1,310 in-wild test events).

## Why this is the right comparison (and the headline model is *not*)

EPSS estimates **P(exploited in the wild within 30 days)**. Our *headline* first-weaponization
label is ~97% public PoC — *exploit tooling appearing*, not a real attack — so comparing it
to EPSS is apples-to-oranges. The project's **in-wild** label (KEV / 0-day / VulnCheck) is
what EPSS actually predicts. This work makes that the target and compares fairly.

## The measurement bug we caught (and fixed)

The first run reported a huge win (+0.294 AUC, EPSS swept at chance). That was an **artifact**:
the harness wrapped EPSS — a *calibrated probability* — inside an xgb-AFT survival fit, which
**collapses to ~chance (AUC@30 0.501)** on this rare/heavily-censored target. The **raw** EPSS
percentile ranks in-wild-within-30d at **0.695**. Fix: a `score_col` passthrough in
`rolling_origin_backtest` ranks by the raw score directly (no model fit). *The same latent flaw
exists in `scripts/inwild_epss_ablation.py`; prior "beats EPSS-only" margins were overstated —
the direction held, but EPSS is a stronger baseline than those runs implied.*

## Results (same in-wild target, 15 origins, 1,310 events)

| Arm | AUC@30 | AUC@90 | PR-AUC@30 | recall@top-1% | recall@top-5% | recall@top-10% |
|---|---|---|---|---|---|---|
| **Structural (ours, no EPSS)** | **0.795** | **0.816** | 0.023 | 0.051 | **0.274** | **0.472** |
| **EPSS** (raw percentile) | 0.695 | 0.683 | 0.018 | **0.068** | 0.213 | 0.271 |
| EPSS xgb-naive (collapsed artifact) | 0.501 | 0.519 | 0.003 | 0.033 | 0.094 | 0.153 |

Paired (structural − EPSS): **AUC@30 +0.100 [0.055, 0.145]**, **AUC@90 +0.134 [0.089, 0.178]**
(both significant); **PR-AUC@30 +0.005 [−0.017, 0.027]** and **PR-AUC@90 +0.014 [−0.013, 0.041]**
(both tied — CI includes 0). At ~1–2% prevalence, AUC is the powered metric for separation and
PR-AUC the deployment metric — so: a real ranking edge, a precision tie.

**Honest reading:** at publication time, our structural signal ranks in-wild risk somewhat
better than EPSS and catches more in the top 5–10%, but EPSS's calibrated probability remains
the sharpest tool at the very top-1% and ties us on precision. This matches the project's prior
independent landmark finding (structural ~0.82 vs EPSS ~0.60 AUC@90).

## The composite ("beat EPSS as a system")

EPSS is a single publication-time score with no notion of pipeline *state*. Our composite is
state-aware:
- **PUBLISHED** (no PoC yet): structural in-wild risk (modestly > EPSS, above) — or keep EPSS at
  the sharp top-1% where it wins. Use the better tool per operating point.
- **POC_PRESENT**: escalate to the **PoC→KEV** model — recall@top-10% **0.50**, ~3d lead
  (`scripts/defender_score.py` STATE 2, `artifacts/merged/defender_operating_points.json`). This
  is a signal EPSS structurally cannot provide.

So the defensible "win" over EPSS is **as a system**: same-or-better at publication, plus a
state-conditional escalation EPSS has no mechanism for.

## What would move the precision tie to a win

The in-wild ceiling is data-limited (~1,310 usable events, ~1–2% prevalence). The lever is **more
in-wild labels**: VulnCheck KEV community (free, ~+1,000–1,700 CVEs, dated events) and GreyNoise
(free research grant; prospective-only, ~90-day window). That is Phase 2.

## Reproduce

```bash
.venv/bin/python scripts/inwild_epss_parity.py        # -> artifacts/inwild_epss_parity.json
.venv/bin/python scripts/defender_score.py            # composite STATE 2 (PoC->KEV escalation)
```
