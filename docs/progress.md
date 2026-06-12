# Progress

Living status + roadmap for the temporal-exploit modeling system. Update as work lands.

Last updated: 2026-06-12.

## Recently landed (this initiative)
- Project `CLAUDE.md`; this `progress.md` roadmap.
- Per-signal labels + competing-risks labels (workstream A1/A2) — decouples PoC from in-wild signals.
- ATT&CK-chain features (B1) and EPSS-at-publication features (B2), both leakage-safe with provenance.
- **`vrs_presence` wired (B4)** — the last unused handover source — as a separate, leakage-flagged `presence_snapshot.parquet` (never merged into the safe features). **All nine handover sources are now used in the dataset.**
- **Fetch layer (C):** `Connector` interface + live connectors for **CISA KEV, EPSS-daily, NVD 2.0** + a `temporal-exploit fetch` CLI subcommand. Live KEV fetch verified against CISA — pulled 1,618 entries dated to yesterday (handover had 1,542).
- CLI `build-dataset` writes `per_signal_labels.parquet`, `competing_risks_labels.parquet`, `presence_snapshot.parquet`; optionally enriches features via `--technique-chain` / `--epss-path`; manifest records which sources were wired.
- Full real build (all nine sources) validated: corpus 338,015; presence 9,009; ATT&CK coverage 25.1%; presence flags confirmed OUT of the safe features; provenance carries both `publication_time_safe` and `snapshot_leakage`.
- Gap fixes from review: empty-frame concat FutureWarning eliminated (labels + nvd); EPSS earliest-row NaN-safe; NVD paging hardened against short/zero pages; NVD `cisa_exploit_added` + real `apiKey` header.
- 67 tests passing (`-W error::FutureWarning`).

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
PoC is 97% of events, so a single first-weaponization model mostly learns PoC/disclosure logistics.
- **A1. ✅ Done.** `build_per_signal_labels` — per-source `{src}_event_date/_observed/_duration_days/_negative_duration_flag`, so each signal is modeled independently. Wired into the CLI (`per_signal_labels.parquet`). Real build: PoC observed 164,761; KEV 1,542; each signal now separable.
- **A2. ✅ Done.** `build_competing_risks_labels` — long-format `(cve_id, published, duration_days, event_cause, cause_code, event_observed)` for lifelines cause-specific hazards / pycox DeepHit. Deterministic `cause_code` (0==censored). Wired into the CLI (`competing_risks_labels.parquet`).
- **A3. ✅ Done.** `build_in_wild_labels` — secondary survival target using only KEV + Google-0day (PoC excluded). Wired into the CLI (`in_wild_labels.parquet`, manifest `in_wild_observed`). Real build: 1,543 confirmed in-wild events (KEV 1,410 + 0-day 133) vs 336,472 censored.
- **A4. ✅ Done.** `evaluate.cascade_order_stats` — for adjacent stages (PoC→MSF→Nuclei→KEV), % where stage a precedes stage b among CVEs observed in both, to motivate multi-state vs independent modeling.

### B. Wire every remaining source
- **B1. ✅ Done.** ATT&CK-chain features from `technique_cwe_chain` (`attack_features.py`): `has_attack_chain_mapping`, `attack_technique_count`, top-k parent-technique one-hot (parent = technique id with sub-technique stripped — lower dimensionality, no external tactic data needed). Wired into the CLI via `--technique-chain`. Real build: coverage 25.1% (matches MITRE-chain coverage). *Tactic-level aggregation deferred — needs the external ATT&CK technique→tactic map (a fetch, workstream D).*
- **B2. ✅ Done.** EPSS-at-publication (`epss_features.py`): first EPSS reading on/after each CVE's `published` (leakage-safe), `epss_at_publication_missing` for pre-2021-04-14/absent CVEs. pyarrow predicate pushdown over the 375M-row file. Wired into the CLI via `--epss-path`. Verified against the real 3.9GB file (sane values, ~9s for a small corpus). *Full-corpus EPSS is a heavier run; treat as an opt-in enrichment.*
- **B3. ✅ Done.** `evaluate.epss_reconciliation` — 2×2 of high-EPSS-at-publication × fast-weaponized (drops EPSS-missing CVEs), for RQ4 (where EPSS over/under-estimates observed weaponization).
- **B4. ✅ Done.** `vrs_presence` wired as the separate leakage-flagged `presence_snapshot.parquet` (see "Recently landed").

### C. Fetch data "till now" (live/incremental)
`src/temporal_exploit/fetch/` package: pluggable connectors that refresh each source to the current date and write to a separate `data/live/` dir (gitignored) without mutating the handover parquets, recording fetch provenance in `fetch_manifest.json`.
- **C1. ✅ Done.** `Connector` ABC + `save` + `write_fetch_manifest`. Network isolated in module-level `_fetch_*` fns (mocked in tests).
- **C2. ✅ Done.** CISA KEV live (`fetch/kev.py`). Verified live (1,618 rows to yesterday).
- **C3. ✅ Done.** FIRST.org EPSS daily CSV.gz (`fetch/epss.py`) → epss_history schema for a given day.
- **C4. ✅ Done.** NVD 2.0 API (`fetch/nvd.py`) → full cve_corpus schema, paged, apiKey header, hardened termination.
- **C5.** Git-mined sources (Metasploit / Nuclei / Trickest / Nomi-sec) + Project Zero — reuse the handover `enrich/` logic; AV-safe `--no-checkout` clones. *(not started — heavier; handover data already covers these sources, just not to today)*
- **C6.** Incremental merge: append live deltas onto the handover parquets into a unified `data/live/` dataset the build can consume (NVD `lastMod` windows, EPSS day-append, KEV full-snapshot dedupe). *(not started)*

### D. More publicly available datasets — DESCOPED
Per scope guidance (2026-06-12): stay within the README's defined sources. New external feeds (OSV, GHSA, ExploitDB, VulnCheck API) are **out of the project's main scope** and parked unless explicitly requested. The "more public data" need is met by live-refreshing the README's own sources (workstream C).

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
