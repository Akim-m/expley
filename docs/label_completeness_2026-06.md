# Label Completeness / False-Censoring — Quantifying the Informative-Censoring Gap

**Date:** 2026-06-21. The in-wild model right-censors every CVE with no catalog
entry as "never exploited." This estimates how many of those are actually
exploited (false negatives) using EPSS — FIRST's calibrated P(exploited in 30d),
trained on exploitation telemetry — as a semi-independent oracle. Reproduce:
`scripts/label_completeness.py` → `artifacts/merged/label_completeness.json`
(snapshot EPSS = the latest reading per CVE, read cheaply from the last daily
row-group of `epss_history`).

## The weaponization funnel (N = 359,507 CVEs)

| stage | CVEs | % |
|---|---|---|
| any signal (PoC/MSF/Nuclei/in-wild) | 169,941 | 47.3% |
| public PoC | 168,744 | 46.9% |
| Metasploit module | 3,124 | — |
| Nuclei template | 4,209 | — |
| **in-wild labeled** (KEV/VulnCheck/0-day/MSRC) | **4,971** | **1.38%** |

## EPSS sees more exploitation than our catalogs capture

Snapshot EPSS, labeled vs UNLABELED CVEs (median EPSS: labeled 0.347, unlabeled 0.002):

| EPSS ≥ | labeled (in-wild) | UNLABELED | 
|---|---|---|
| 0.1 | 3,055 | 19,556 |
| 0.3 | 2,559 | 8,417 |
| **0.5** | **2,229** | **4,902** |
| 0.7 | 1,864 | 2,496 |
| 0.9 | 1,035 | 338 |

Calibrated expectation — **sum(EPSS) ≈ expected # exploited in a 30-day window:**
labeled **2,124**, **UNLABELED 9,046**. The unlabeled exploitation mass EPSS sees
is **~2× our entire labeled in-wild set.**

**The unlabeled high-EPSS cohort is OLD, not catalog-lag:** of the 4,902 unlabeled
EPSS≥0.5 CVEs, **97% (4,761) were published >1 year before the snapshot** (90%
>2 years; median age ~3,700 days). They had ample time to be cataloged and weren't
— so this is genuine label incompleteness, not listing delay. Their median EPSS is
0.71; 337 sit at EPSS≥0.9.

## Interpretation

- **The 1.38% in-wild rate under-counts true exploitation.** A calibrated oracle
  indicates roughly **2,500–9,000 exploited-but-uncataloged CVEs** — comparable to
  or exceeding our 4,971 labeled. So the ceiling is **partly false-censoring, not
  purely "exploitation is rare."** This is the **informative-censoring** problem the
  framing doc flags, now quantified: we likely mislabel a count of true positives
  comparable to our whole positive set as censored.
- **Effect on the model:** the absolute event rate / calibration is biased LOW
  (missing positives), and ranking is partly affected (some "negatives" are real
  positives). Discrimination (AUC) is more robust to symmetric label noise than
  calibration is — consistent with the project's "AUC holds, calibration is the
  open frontier" finding.

## Why this is NOT a cheap fix (two honest catches)

1. **EPSS circularity.** We cannot relabel using high EPSS — the model's purpose is
   to *complement* EPSS, not distill it; EPSS-derived labels would make it an
   EPSS-copy. (See the framing caveat in CLAUDE.md.)
2. **EPSS over-prediction at the old tail.** Some of the 4,900 are persistently
   scanned legacy CVEs EPSS over-scores, not confirmed exploitation. The true
   missed-positive count lies between ~337 (EPSS≥0.9) and ~4,900 (EPSS≥0.5).

## Reconciliation with the source-saturation finding

Catalogs are saturated (CISA/VulnCheck KEV already aggregate the universe; MSRC and
ENISA EUVD added **0** new — see `msrc_integration_2026-06.md`), yet EPSS sees
~5–9k more exploited CVEs. Those missing labels are exactly the
**un-cataloged-but-telemetry-observed** exploitation that only **sensor feeds**
(GreyNoise / Shadowserver / VulnCheck `ipintel`) would confirm — and those are the
paid/keyed modality we cannot access. So:

**The honest bottom line:** the in-wild ceiling is data-bound, and a *material part*
of it is label incompleteness (false-censoring), not just rarity. Closing it
requires exploitation **telemetry** (a different modality), not more catalogs and
not EPSS-relabeling. Absent that, the defensible move is to **report the in-wild
results as a lower bound** and lean on the abundant, well-labeled
first-weaponization / PoC→KEV heads where censoring is far less informative.
