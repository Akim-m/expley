# Progress

Living status + roadmap for the temporal-exploit modeling system. Update as work lands.

Last updated: 2026-06-12.

## Done

### Modeling core (merged to `master`)
- **Package + tooling** — `pyproject.toml`, `src/temporal_exploit/` package, console script, pytest config.
- **Loaders + schema** — `load_parquet`, `load_required_parquets`, `validate_columns` with real handover column names. Fails loudly on missing columns.
- **Labels** — `build_first_weaponization_labels`: earliest event across the five dated sources, UTC-normalized, right-censoring at snapshot, `negative_duration_flag` (preserved not dropped).
- **Features** — `build_publication_features`: leakage-safe publication-time metadata (CVSS + missing indicator, severity one-hot, CWE/vendor/product counts, year). `feature_provenance()` audit trail. ndarray-safe list handling.
- **Splits** — time-based on `published`, locked `train/test_cve_ids.txt` + metadata. UTF-8.
- **Baselines** — Kaplan-Meier + Cox PH (lifelines), both reject negative durations.
- **Evaluation** — `event_rate_by_horizon` (7/30/90/180), `event_source_counts`.
- **CLI** — `build-dataset` builds labels + features + manifest, optional locked splits, always writes `feature_provenance.csv`.
- **Docs** — `docs/modeling_methodology.md` (verified accurate), README quick start, project `CLAUDE.md`.
- **Quality** — 34 tests; every phase passed two-stage review; validation gate run on the real 338k-row dataset (CVSS mean 4.98, non-zero list counts, PoC-dominant events).

### Critical defects fixed (found in first review)
- tz-aware date crash in label builder.
- wrong schema column names (`dateAdded`→`kev_date_added`, `date_discovered`→`zeroday_date_discovered`).
- wrong feature columns (`cvss_v3_base_score`→`cvss_v3_base`, `weaknesses`→`cwe_ids`) with silent zero-degradation.
- `list_len` returning 0 for numpy arrays.

## Data sources — wiring status

| Source | Parquet | Used today | Target |
|---|---|---|---|
| CVE corpus (NVD/VulnCheck) | `cve_corpus` | ✅ features + clock origin | keep |
| PoC (Trickest + Nomi-sec) | `poc_dates` | ✅ event source | split out as its own competing risk |
| Metasploit | `metasploit_dates` | ✅ event source | per-signal target |
| Nuclei | `nuclei_dates` | ✅ event source | per-signal target |
| CISA KEV | `kev_events` | ✅ event source | per-signal target + secondary in-wild label |
| Google 0-day | `google_0day` | ✅ event source | per-signal target + secondary in-wild label |
| EPSS history | `epss_history` | ❌ unused | EPSS-at-publication feature (leakage-safe) + reconciliation |
| ATT&CK chain | `technique_cwe_chain` | ❌ unused | tactic-level one-hot features + `has_attack_chain_mapping` |
| VRS presence | `vrs_presence` | ❌ unused | descriptive / censored-rows-only (snapshot leakage) |

## In progress / next (this initiative)

Four workstreams from the directive "more public datasets, fetch till now, deal with PoC timing, wire every source." Ordered by value/risk.

### A. Deal with PoC timing (highest priority — it's the core framing problem)
PoC is 97% of events, so a single first-weaponization model mostly learns PoC/disclosure logistics. Plan:
- **A1.** Per-signal duration/event columns: `duration_to_{poc,metasploit,nuclei,kev,google_0day}` + observed flags, so each transition can be modeled independently. *(pure pandas, TDD)*
- **A2.** Competing-risks label builder: long-format `(cve_id, cause, duration, observed)` suitable for lifelines `AalenJohansenFitter` / cause-specific hazards and pycox DeepHit. *(pure pandas, TDD)*
- **A3.** Secondary "confirmed in-wild" target = earliest of KEV/Google-0day only (the ~664 true-exploitation events), with explicit small-sample warning in evaluation.
- **A4.** Cascade analysis helper: PoC→MSF→Nuclei→KEV ordering stats (how often each precedes the next) to motivate multi-state vs independent modeling.

### B. Wire every remaining source
- **B1.** ATT&CK tactic features from `technique_cwe_chain`: map technique→tactic, one-hot at tactic level (lower dimensionality than 174 techniques), plus `has_attack_chain_mapping` boolean (the ~75% with no mapping is a feature, not absence). *(pure pandas, TDD)*
- **B2.** EPSS-at-publication feature from `epss_history`: first EPSS reading on/after each CVE's `published` (leakage-safe), with `epss_at_publication_missing` for pre-2021-04-14 CVEs. Read via pyarrow predicate pushdown — never load 375M rows. *(TDD with tiny fixture)*
- **B3.** EPSS reconciliation report: where snapshot EPSS over/under-estimates observed weaponization (descriptive, RQ4).

### C. Fetch data "till now" (live/incremental)
New `src/temporal_exploit/fetch/` package: pluggable connectors that refresh each source to the current date, append to the handover parquets without mutating originals (write to a separate `data/live/` dir), and record fetch provenance (source, fetched_utc, row delta) in a manifest.
- **C1.** Connector interface + manifest + caching/rate-limit handling. Network calls mocked in tests.
- **C2.** CISA KEV live (single public JSON, no auth) — simplest, establishes the pattern.
- **C3.** FIRST.org EPSS live (daily CSV.gz API) — extends `epss_history` to today.
- **C4.** NVD 2.0 API (CVE corpus refresh; needs `lastModStartDate` paging, optional API key, 6s/30s rate limits).
- **C5.** Git-mined sources (Metasploit / Nuclei / Trickest / Nomi-sec) — reuse the handover `enrich/` logic; AV-safe `--no-checkout` clones.

### D. More publicly available datasets (new sources)
- **D1.** OSV.dev — cross-ecosystem advisories with affected version ranges + references (public API, no auth). Adds non-NVD coverage and earlier PoC/fix references.
- **D2.** GitHub Security Advisories (GHSA) — GraphQL API; CWE, severity, references, withdrawal dates.
- **D3.** ExploitDB — public CSV of exploit publication dates per CVE; a sixth dated weaponization signal (real exploits, not just PoC index entries).
- **D4.** (stretch) VulnCheck Community / KEV API, CISA KEV "known ransomware" flag enrichment.

## Scope for improvement (backlog / quality)
- Artifact content hashes in `manifest.json` for reproducibility.
- Event-source dominance warning emitted at build time when one source >X% of events.
- Cox proportional-hazards diagnostics (`check_assumptions`) wired into a report before coefficient interpretation.
- Calibration plots (Brier / reliability) at 7/30/90/180 days.
- Description-text leakage mitigation (mask KEV/"actively exploited" terms; restrict text features to `last_modified ≤ published + ε`) before any NLP feature.
- Deep survival models (DeepHit/DeepSurv via pycox) vs Cox, once competing-risks labels exist.
- CI workflow running the test suite; pre-commit hooks.
- Replace the `--basetemp`/`no:cacheprovider` pytest workaround with a proper `tmp_path` config or move the checkout off OneDrive.

## Conventions
- TDD, one focused commit per change, two-stage review for non-trivial work.
- Leakage discipline and tz/column-name rules per `CLAUDE.md`.
- Generated data (`artifacts/`, `data/live/`) stays gitignored.
