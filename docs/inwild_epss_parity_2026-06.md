# In-wild EPSS parity: do we beat EPSS on the same target? (2026-06)

**TL;DR.** On a **publication-anchored known-exploited target** — the closest honest proxy we
have for what EPSS predicts, in practice ~93% VulnCheck-KEV catalog membership plus CISA KEV,
scored within 30/90 days of publication — our publication-time structural model **beats EPSS on
ranking by a modest, significant margin** (+0.100 AUC@30 [0.055, 0.145]; +0.134 AUC@90
[0.089, 0.178]), is **statistically tied on precision** (PR-AUC), and **loses the very sharp top**
(EPSS wins recall@top-1%). It is a complement / modest improvement, **not** a blowout. The result
is **reproducible to the digit and deterministic** (zero run-to-run jitter), the head-to-head is
**methodologically fair** (identical per-origin test rows/labels for both arms, correct raw-EPSS
baseline, no leakage, EPSS not starved by missingness), and the win **survives adversarial
re-verification** (see *Robustness*). Source: `scripts/inwild_epss_parity.py` →
`artifacts/inwild_epss_parity.json` (15 walk-forward origins, 1,310 test events).

## Why this is the right comparison (and the headline model is *not*)

EPSS estimates **P(exploited in the wild within 30 days)**. Our *headline* first-weaponization
label is ~97% public PoC — *exploit tooling appearing*, not a real attack — so comparing it
to EPSS is apples-to-oranges. The project's **in-wild** label (KEV / 0-day / VulnCheck) is the
closest thing we have to what EPSS predicts, and this work makes that the target and compares fairly.

**But be honest about what the label actually is** (adversarial RE, 2026-06-30). It is a *proxy*,
not literally "exploited within 30 days":
- **It is predominantly VulnCheck.** Of the 1,310 kept test events, **~1,220 (93%) are VulnCheck-KEV
  catalog membership**, **90 are CISA KEV**, and **Google 0-day contributes zero** kept test events
  (all 132 are exploited *before* publication → negative-duration → dropped by
  `prepare_modeling_frame`). So "(KEV / 0-day / VulnCheck)" is in practice *predominantly VulnCheck KEV*.
- **The event date is an administrative catalog-add date, not exploitation onset.** Among kept test
  events the median duration (add − published) is **175 days**, and only **~22% fall inside the 30-day
  horizon** (VulnCheck median lag +107d; CISA +329d). So AUC@30 is largely ranking *eventual* known-
  exploited status, not crisp 30-day onset. Read the target as a **publication-anchored known-exploited
  proxy**, and note this if anything *understates* EPSS (it is scored against a catalog-timing proxy of
  its true objective). The comparison is fair (both arms see the identical proxy); the *name* is the
  soft part, not the number.

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

## Robustness (adversarially re-verified, 2026-06-30)

Two independent adversarial RE passes tried to *break* the corrected +0.100 win (the whole reason
this work exists is that the *first* run's +0.294 was a measurement artifact). Both confirmed it,
and surfaced the *mechanism*:

- **Reproduces deterministically.** A from-source re-run gives structural AUC@30 0.795344, EPSS
  0.695282, paired delta +0.100061 [0.0553, 0.1449], win 13/15 origins — **byte-identical** to the
  committed artifact; 3 extra structural re-fits gave **zero** run-to-run variance. The win is not
  nondeterminism jitter.
- **No EPSS coverage handicap** (the most plausible fake-win mechanism). Missing EPSS is imputed to
  percentile 0.0, but in-wild positives have **99.9% publication-time EPSS coverage** (1/1,310 missing;
  **0** of the AUC@30-driving positives missing). Restricting *both* arms to real-EPSS-only rows
  **widens** the gap (+0.100→**+0.106** AUC@30, +0.134→**+0.137** AUC@90) — the opposite of a coverage
  artifact.
- **No structural leakage.** The structural arm trains on 68 columns, all on the CLAUDE.md
  publication-time-safe list (CVSS/CWE/CPE/ATT&CK one-hots); **no** description text, **no**
  `vrs_presence`, **no** snapshot EPSS. The two arms are scored on **identical per-origin test frames**
  (same `cve_id`/duration/event), and the paired CI is genuinely paired on the shared origin key.
- **The honest mechanism.** In-wild positives sit at a **median publication-time EPSS percentile of
  just 0.168** — EPSS is a *dynamic* score that climbs as telemetry accumulates, and at disclosure time
  (t=0, before any telemetry exists) it has not yet reacted to the eventual positives. The CVE's
  intrinsic CVSS/CWE/CPE structure *is* fully present at t=0, so structural features genuinely
  out-rank EPSS *at the cold-start moment a defender most needs a signal*. That is the legitimate
  framing of the win — not "smarter than EPSS," but "better at t=0, where EPSS has nothing to react to."

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
structural-vs-EPSS CI** (width 0.20 → 0.09; delta SE 0.051 → 0.023) and turned a barely-significant
win into a solid one — but it **did not change the gap's magnitude** (+0.10 either way) and **did not
break the precision (PR-AUC) tie** (CISA-only PR-AUC@30 is actually a dead heat, +0.001 wrong way).
More labels bought *reliability*, not a bigger win. The data-limited ceiling is on the **gap**,
consistent with the project's recurring finding (cf. `fig_vulncheck_lift`).

**Caveat on what those extra labels are.** The ~885 VulnCheck events that tightened the CI are
**lower-timing-quality**: median add-minus-publish lag +107d, **>1/3 added more than a year** after
publication (CISA KEV is no cleaner — median +329d). The CI tightened because *n* grew, not because
the labels are 30-day-onset-crisper; the +0.10 gap is stable across the two label sets precisely
because both share the same administrative-timing weakness. This is why the right reading of the
target is a *publication-anchored known-exploited proxy* (above), and why the next real lever is an
**earlier, onset-accurate** in-wild signal (telemetry), not simply more catalog memberships.

## What would move the precision tie to a win

VulnCheck (above) did not — it sharpened confidence, not the margin. The remaining label lever is
**GreyNoise** — and its API was verified end-to-end (2026-06-30, [`greynoise_inwild_2026-06.md`](greynoise_inwild_2026-06.md)).
Finding: the free Research-Community grant *does* give Enterprise CVE-API access, **but the in-wild
observation data is a rolling ≤30-day window with no per-CVE first-observed date** — the only
historical per-CVE date is *first exploit-code published* (tooling, = our first-weaponization
signal, not in-wild). So GreyNoise **cannot backfill history**; it is a *prospective* stream. We
built `fetch/greynoise.py` as a forward accumulator (ready + tested) so the project can start
banking onset-accurate labels going forward, but it adds **0 historical events** and does not move
this result. Net: with CISA KEV + VulnCheck + 0-day already integrated and GreyNoise confirmed
backfill-incapable, we are **at the honest data ceiling** for this *historical* comparison — a
bigger win needs a fundamentally larger/earlier in-wild signal accumulated prospectively, not a
fancier model.

## Reproduce

```bash
.venv/bin/python scripts/inwild_epss_parity.py        # -> artifacts/inwild_epss_parity.json
.venv/bin/python scripts/defender_score.py            # composite STATE 2 (PoC->KEV escalation)
```
