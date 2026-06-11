# Modeling methodology

This document describes how the temporal exploit modeling layer turns the
handover parquet files into a survival-analysis dataset, the choices that keep
it leakage-safe and reproducible, and the biases an analyst must keep in mind
when interpreting results. It is written to stand on its own — you do not need
to read the code to follow it.

## 1. Target

The prediction target is the **time from CVE publication to the first public
weaponization signal**. The signal is the earliest of five dated event sources:

- public proof-of-concept (`poc_dates.poc_first_seen`)
- Metasploit module availability (`metasploit_dates.metasploit_first_seen`)
- Nuclei template availability (`nuclei_dates.nuclei_first_seen`)
- CISA KEV inclusion (`kev_events.kev_date_added`)
- Google Project Zero 0-day discovery (`google_0day.zeroday_date_discovered`)

For each CVE the earliest dated event across these sources becomes the observed
event; `event_source` records which source produced it. If a CVE has no event
from any source it is right-censored (see Censoring below).

## 2. Clock origin

The clock origin for every CVE is `cve_corpus.published`. Duration is measured
in whole days from `published` to the event date (or to the snapshot date for
censored CVEs).

All dates — the publication timestamp, every event date, and the snapshot date
— are normalized to UTC before any arithmetic. The handover parquet date
columns are already tz-aware UTC timestamps; naive inputs are localized to UTC
so duration subtraction never mixes tz-aware and tz-naive values.

## 3. Censoring

CVEs without an observed event are **right-censored at the snapshot date**.
Their `event_source` is set to `"censored"`, `event_observed` is `False`, and
their duration is the number of days from publication to the snapshot.

Censoring here is **potentially informative**: older CVEs have had longer
exposure and are therefore more likely to have accumulated a public signal,
while recently published CVEs are censored simply because little time has
passed. Standard survival estimators assume non-informative censoring, so this
caveat matters when interpreting curves and coefficients.

## 4. Negative durations

Some events are dated **before** the CVE's publication date (pre-disclosure
signals, backdated feeds, or metadata revisions). These rows produce a negative
duration. They are **flagged** via `negative_duration_flag` and **preserved**,
not silently dropped — keeping them visible exposes data-quality issues instead
of hiding them.

Because survival fitters reject negative durations, **callers must exclude
flagged rows before fitting** any baseline. The fit helpers do not drop rows
themselves: silent dropping inside a fitter would mask the underlying data
problem, so the responsibility stays with the caller.

## 5. Leakage controls

Features are restricted to **publication-time structured metadata** — values
knowable at or near disclosure. The feature set is:

- `cvss_v3_base` — the CVSS v3 base score, with missing scores imputed to `0.0`
- `cvss_v3_missing` — an indicator that the base score was missing (so the
  `0.0` imputation is not conflated with a genuinely low severity)
- `severity_*` — one-hot encoding of `cvss_v3_severity` (missing → `UNKNOWN`)
- `has_weakness` / `weakness_count` — presence and count from `cwe_ids`
- `vendor_count` — count from `vendors`
- `product_count` — count from `products`
- `published_year` — year of publication

Deliberately **excluded** to prevent temporal leakage:

- CVE description text (descriptions are revised over time and can carry
  post-event mentions such as KEV or active-exploitation language)
- snapshot-time feed-presence flags (whether a source eventually listed the CVE)
- snapshot-time EPSS scores

`feature_provenance()` is the audit trail: it returns one row per emitted
feature family with its source column and a `leakage_status` of
`publication_time_safe`, so every feature's origin can be reviewed.

## 6. Splits

Train/test partitioning is **time-based on `published` at a fixed cutoff date**:
CVEs published before the cutoff form the train set, those on or after it form
the test set. This respects the temporal ordering — a model is only ever
evaluated on CVEs published later than those it trained on.

The split is **locked**: when a cutoff date is supplied to the build via
`--cutoff-date`, the CVE IDs are written to `train_cve_ids.txt` and
`test_cve_ids.txt` alongside a `split_metadata.json` recording the cutoff date
and the train/test counts. **No random K-fold** splitting is used, because
random folds would let future CVEs leak into training.

## 7. Baselines

Two classical survival baselines:

- **Kaplan-Meier** — a non-parametric reference survival curve for first
  weaponization, fit on `duration_days` and `event_observed`. It is the
  unconditional time-to-event baseline.
- **Cox proportional hazards** — fit on the numeric features to estimate how
  covariates shift the hazard.

The **proportional-hazards assumption must be checked before interpreting Cox
coefficients**. Run `fitter.check_assumptions(...)` on the fitted model; if
covariates violate proportional hazards, the coefficients are not
interpretable as constant hazard ratios and require stratification or
time-varying terms. Negative-duration rows must be excluded before fitting
either baseline (see Negative durations).

## 8. Evaluation horizons

Models are evaluated at fixed horizons of **7, 30, 90, and 180 days**.

The **naive event-rate-by-horizon** is the floor any model must beat: for each
horizon it reports the fraction of CVEs with an observed event on or before that
many days. A model that cannot improve on this unconditional rate is not adding
value. An event-source composition summary accompanies it, reporting the count
and percentage of CVEs per `event_source` (including `censored`).

## 9. Known biases

- **PoC source dominance.** Public proof-of-concept publication is by far the
  most common signal, so the target is heavily shaped by PoC timing rather than
  by the rarer Metasploit/Nuclei/KEV/0-day events.
- **Public-signal framing.** The target measures *public weaponization
  capability*, not confirmed *in-the-wild exploitation*. A public PoC is not
  evidence of active attacks.
- **NVD metadata revisions.** CVSS scores, CWE mappings, and affected
  vendor/product lists are revised over time. The structured metadata used as
  features reflects its current state, not necessarily its state at publication.

## 10. Production-novelty contributions

Beyond the modeling itself, the pipeline adds reliability and auditability:

- **Schema validation** — required columns are checked on load, so wrong or
  missing columns fail loudly instead of silently degrading to empty features.
- **Artifact manifests** — each dataset build writes a `manifest.json` with the
  snapshot date, row counts, and per-source event counts.
- **Feature provenance** — every build writes `feature_provenance.csv`,
  documenting each feature family with its source column and leakage status.
- **Locked splits** — when `--cutoff-date` is supplied, the build writes
  `train_cve_ids.txt`, `test_cve_ids.txt`, and `split_metadata.json`, making
  splits reproducible across runs.
- **Negative-duration flags** — data-quality issues are surfaced and preserved
  rather than dropped.

## 11. Observed label composition (snapshot 2026-03-14)

First build over the full handover corpus (338,015 CVEs):

| Event source | Count |
| --- | --- |
| censored | 172,539 |
| poc | 160,873 |
| metasploit | 2,246 |
| nuclei | 1,693 |
| kev | 531 |
| google_0day | 133 |

- **Observed events:** 165,476 of 338,015 CVEs (~49%); the rest are right-censored
  at the snapshot.
- **PoC dominance is extreme:** public PoC accounts for ~97% of observed events.
  This is the single most important framing caveat — the model overwhelmingly
  learns *time to public PoC*, not time to confirmed exploitation. KEV and
  Google 0-day signals are rare (531 and 133 first-events respectively).
- **Negative durations:** 3,255 CVEs have an event dated before publication
  (flagged via `negative_duration_flag`, minimum −3,505 days). These must be
  excluded or analyzed separately before fitting survival models.
- **Missing CVSS:** 94,508 CVEs (~28%) lack a CVSS v3 base score; these are
  imputed to 0.0 with the `cvss_v3_missing` indicator set so the imputation is
  recoverable downstream.

The per-source counts above are first-events-per-CVE (after deduplication and
earliest-event selection); the manifest's `event_source_rows` instead records
raw input rows per parquet, so the two differ.
