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

## VulnCheck label lift (measured): more labels tighten the win, don't widen it

VulnCheck KEV is **already wired and fetched** (`src/temporal_exploit/fetch/vulncheck.py` →
`data/live/vulncheck_kev.parquet`, 4,969 CVEs, fetched 2026-06-20 with the token via the
`/v3/backup/vulncheck-kev` catalog + earliest `vulncheck_reported_exploitation[].date_added`),
and it is **already in the headline result above**. Running the parity on **CISA-only** vs
**CISA + VulnCheck + 0-day** in-wild labels isolates what those labels bought
(`INWILD_SUBSET=kev` vs default; `artifacts/inwild_epss_parity_kev.json` vs `…_parity.json`):

| In-wild labels | test events | structural AUC@30 | EPSS AUC@30 | structural − EPSS |
|---|---|---|---|---|
| CISA KEV only | 425 | 0.769 | 0.662 | +0.107 [0.007, 0.208] |
| + VulnCheck + 0-day | 1,310 | 0.795 | 0.695 | +0.100 [0.055, 0.145] |

VulnCheck roughly **tripled the usable in-wild events** (425 → 1,310), which **roughly halved the
structural-vs-EPSS CI** (width 0.20 → 0.09) and turned a barely-significant win into a solid one —
but it **did not change the gap's magnitude** (+0.10 either way) and **did not break the precision
(PR-AUC) tie**. More labels bought *reliability*, not a bigger win. The data-limited ceiling is on
the **gap**, consistent with the project's recurring finding (cf. `fig_vulncheck_lift`).

## What would move the precision tie to a win

VulnCheck (above) did not — it sharpened confidence, not the margin. The remaining label lever is
**GreyNoise**, but it needs the free Research-Community grant (manual approval) and only exposes a
~90-day rolling CVE window, so it is a *prospective* telemetry stream, weak for historical
backfill. Net: with CISA KEV + VulnCheck + 0-day already integrated, we are near the honest
data ceiling for this comparison; a bigger win likely requires a fundamentally larger/earlier
in-wild signal, not a fancier model.

## Reproduce

```bash
.venv/bin/python scripts/inwild_epss_parity.py        # -> artifacts/inwild_epss_parity.json
.venv/bin/python scripts/defender_score.py            # composite STATE 2 (PoC->KEV escalation)
```
