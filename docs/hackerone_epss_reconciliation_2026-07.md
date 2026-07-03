# HackerOne Hacktivity as an EPSS-reconciliation lens

*2026-07-04. Reproducible: `scripts/hackerone_epss_reconciliation.py` (writes `artifacts/hackerone_epss_reconciliation.json`).*

## Question

Does HackerOne Hacktivity (public bug-bounty **coordinated-disclosure** reports) give an
in-the-wild exploitation signal that our data lacks — and does it help **vs EPSS**?

## Source and access (verified 2026-07-04)

`hackerone.com/graphql`, **unauthenticated, introspection open**.
- **Wrong feed for history:** `ranked_cve_entries` (the `cve_discovery`/`cwe_discovery` pages)
  exposes only a **rolling ~24-week** submission window, identical for every CVE — a
  GreyNoise-style no-history dead-end — and re-surfaces `epss`/`cvss`/`cwe` we already have.
- **Right feed:** `search(index: CompleteHacktivityReportIndex)` → `HacktivityDocument`
  (`cve_ids, cwe, severity_rating, submitted_at, disclosed_at`) — genuine per-report history
  back to 2013. Cursor paging is capped at 50 rows; **offset paging (`from`/`size`) bypasses it**;
  ES `max_result_window`=10k means `disclosed_at` date-slicing is the fallback for larger sets.
- Scale of the addressable set: **only 1,933 disclosed reports carry a CVE id.** We pulled 1,799
  (throttled 3 s/req, 429/503 backoff, no rate-limiting) → **1,725 unique CVEs, 1,658 in corpus (96 %)**.

## Findings

| Measurement | Value | Meaning |
|---|---|---|
| In-wild (KEV) rate — corpus | 0.46 % | base rate |
| In-wild rate — HackerOne CVEs | **4.10 % (9.0× lift)** | H1 CVEs are *more* exploited, not less — a "serious-vuln attention" marker, **not** a benign one |
| New in-wild **labels** added | **0** (68 overlap KEV, all pre-labelled) | does **not** move the ~396-event in-wild ceiling |
| Pub-time EPSS of H1∩in-wild | median pctile **0.036**; 54 % in EPSS bottom-10 % | the in-wild CVEs H1 touches are ones **EPSS under-ranks** |
| **EPSS blind-spot test** (pub-EPSS pctile < 0.1) | KEV rate **H1 3.92 % vs non-H1 0.45 % → 8.8× lift**; **37 exploited CVEs** in EPSS's bottom decile | the real "helps vs EPSS" result |
| Leakage-safe fraction (`disclosed_at ≤ published`) | **42 %** | ~42 % of the signal is publication-time-knowable, not future |
| CWE clusters of the 37 | CWE-22, -20, -502, -306, -78, -94, -326 | traversal / deserialization / injection RCE |
| Named blind-spot CVEs | **CVE-2017-5638 (Apache Struts / Equifax)**, 2017-10271 (WebLogic), 2017-11317 (Telerik), 2017-9841 | famous exploited RCEs EPSS cold-started in its bottom decile |

## Verdict

**Real and complementary to EPSS, but sparse and analysis-grade — not a modelling feature.**

- The user's intuition holds in a *specific reframe*: not "discovered ⇒ not exploited," but
  **"bug-bounty attention lights up exactly where EPSS is blind"** (serious server-side RCEs EPSS
  scored low at publication that were later exploited). 8.8× blind-spot lift is genuine.
- Two hard limits keep it out of the model: **(1) volume** — 1,658 CVEs, only 37 in the blind spot;
  **(2) probable redundancy** — the signal ("serious RCE that drew attention") is likely already
  carried by our CVSS/CWE/PoC structural features, which *already* beat EPSS by +0.100 AUC@30 on the
  in-wild target. "Helps vs EPSS" ≠ "helps vs our model."
- Temporal skew caveat: the blind-spot examples are mostly 2017 CVEs (older CVEs have had time to
  accumulate KEV status and had immature early-era EPSS) — so this illustrates EPSS's *cold-start*
  blind spot specifically.

**Where it belongs:** the project's explicit **EPSS-reconciliation deliverable** (Project Plan slides 4 & 7)
— a quantified, citable case study of *where and why EPSS misses*, with named CVEs and CWE clusters.

## Ablation — RUN, prediction confirmed (null)

`scripts/inwild_h1_ablation.py` (→ `artifacts/inwild_h1_ablation.json`). Leakage-safe flag
`h1_pub_report` (a publicly disclosed HackerOne report existed on/before CVE publication,
`disclosed_at ≤ published`) added to the **structural, no-EPSS** in-wild model; same corpus,
same 15 walk-forward origins, same xgb-AFT, only the extra column changes.

| Horizon | Structural | + H1 flag | Δ (95% CI) |
|---|---|---|---|
| AUC@30 | 0.7951 | 0.7933 | **−0.0018** [−0.0055, +0.0020] |
| AUC@90 | 0.8163 | 0.8179 | **+0.0016** [−0.0022, +0.0055] |

Flag prevalence 700/338,015 (0.21 %); 1,310 test events. **Pre-registered prediction (≤ +0.005 AUC@30)
confirmed:** both CIs straddle zero, |Δ| < 0.002 — the flag adds **nothing** over the structural model.

**Reading:** the HackerOne signal is real *vs EPSS* (9× blind-spot lift) but **redundant with the
CVSS/CWE/PoC structural features** — which is *why* our structural model already beats EPSS. This
strengthens (not weakens) the reconciliation story: EPSS misses these CVEs; a model with the structural
features does not. HackerOne is a narrative lens on *where EPSS is blind*, not a feature that buys lift.

**RE-verified (feature-pathway control).** To rule out a dropped-column artifact, the same harness was
re-run with two synthetic augments: an **oracle** (in-wild/KEV membership) moved AUC@30 0.7951 → **0.8656
(+0.0705)**, and a **noise** column moved it **−0.0008**. The H1 flag's −0.0018 sits with *noise*, not the
oracle — the augment pathway works and the null is genuine (the flag is truly uninformative given the
structural features), not a plumbing bug.

## Do-not-re-attempt note

HackerOne is now characterised (memory: `hackerone-hacktivity-checked`). It is **not** an in-wild
label source (0 new labels) — do not build a modelling connector on that premise. Siblings:
Shadowserver (region-locked), GreyNoise (prospective-only).
