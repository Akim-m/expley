# Temporal Exploit Prediction

A leakage-safe survival-analysis pipeline that predicts **when** a published CVE
becomes publicly weaponized — a time-to-event problem, not the usual binary
"will it be exploited" framing.

Security teams already have tools that estimate whether a vulnerability is
severe or likely to be exploited. This project asks a different question:

> After a CVE is published, *when* does public exploitation capability appear?

## Highlights

- **Scale.** A reproducible dataset builder over a **338,015-CVE corpus**,
  fusing nine security data sources; 164,761 public proof-of-concept dates and
  1,543 confirmed in-the-wild exploitation events are observed across the
  timeline.
- **Nine fused sources.** NVD/CVE metadata, public PoC publication, Metasploit,
  Nuclei, CISA KEV, Google Project Zero 0-days, daily EPSS history, and MITRE
  CWE→CAPEC→ATT&CK chains.
- **Correct survival methodology.** Right-censoring at a fixed snapshot date,
  competing-risks labels for the PoC → Metasploit → Nuclei → KEV progression,
  and Kaplan-Meier / Cox proportional-hazards baselines evaluated at 7/30/90/
  180-day horizons.
- **Leakage discipline.** Only publication-time-safe features are used for
  prediction; snapshot-time feed-presence flags and post-event description text
  are excluded. A `feature_provenance()` audit tags every feature
  `publication_time_safe` vs `snapshot_leakage`, and splits are time-based
  (locked train/test), never random K-fold.
- **Data engineering.** Pluggable live-fetch connectors (CISA KEV, FIRST.org
  EPSS, NVD 2.0 API) and a 3.9 GB / 375M-row EPSS history processed via Arrow
  predicate pushdown. Covered by 18 pytest modules run under warnings-as-errors.

## Tech stack

Python (packaged `src/` layout, `pyproject.toml`, console script) · pandas ·
pyarrow (predicate pushdown) · lifelines (Kaplan-Meier, Cox PH) · pytest.

## Why timeline, not just "exploited?"

Most observable events are public PoC or tooling signals rather than confirmed
in-the-wild exploitation, so the strongest, most honest framing is **timeline
to public weaponization**. This complements EPSS rather than competing with it:
EPSS predicts exploitation probability in a fixed 30-day window, while this
project models weaponization *timing* and can surface CVEs where EPSS is high
but weaponization is slow (or low but fast).

## Methodology (summary)

1. **Stabilize the handover data** — confirm the nine parquet sources, keep
   generated multi-GB data out of Git, document provenance, bias, and leakage
   risk per source.
2. **Build the analysis dataset** — `cve_corpus.parquet` as the per-CVE base
   table, `published` as the clock origin, joined to dated event sources; define
   time-to-event labels and right-censor CVEs with no observed event.
3. **Avoid temporal leakage** — publication-time features only; exclude
   snapshot-time feed flags and post-event description text; time-based splits.
4. **Exploratory analysis** — Kaplan-Meier curves per event definition; timing
   by CVSS severity, CWE class, vendor/product, and ATT&CK tactic; quantify
   censoring and PoC dominance.
5. **Baseline survival models** — Kaplan-Meier references, Cox PH, random
   survival forest; evaluate discrimination and calibration at fixed horizons.
6. **Stronger models (optional)** — DeepSurv / DeepHit and competing-risk /
   multi-state models for the PoC→Metasploit→Nuclei→KEV progression.
7. **Reconcile against EPSS** — compare multi-horizon predictions; frame EPSS as
   complementary.
8. **Final outputs** — a reproducible dataset builder, locked train/test CVE-ID
   splits, survival notebooks, evaluation tables, and a written methodology
   covering censoring, leakage, event definitions, and source bias.

## Modeling quick start

```bash
python -m pip install -e ".[dev]"
temporal-exploit build-dataset \
  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \
  --artifact-dir artifacts \
  --snapshot-date 2026-03-14
pytest
```

Generated artifacts land in `artifacts/` (Git-ignored): `modeling_labels.parquet`,
`publication_features.parquet`, and `manifest.json`. Full methodology is in
`docs/modeling_methodology.md`.

## Repository layout

```text
dataset_extraction-.../dataset_extraction/
  extract/     Mongo/VRS extraction scripts
  enrich/      external timestamp and metadata enrichment
  handover/    data dictionary
  out/         generated parquet outputs (Git-ignored)
src/           packaged pipeline: fetch/, labels.py, features.py, splits.py,
               baselines.py, evaluate.py, epss_features.py, attack_features.py
docs/          modeling_methodology.md
```

Large generated datasets (parquet outputs, EPSS dumps) are intentionally
Git-ignored and handled as local or object-storage artifacts.
