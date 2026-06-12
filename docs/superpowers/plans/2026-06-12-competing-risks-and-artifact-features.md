# Competing-Risks Modeling + Artifact Features + Label Connectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the verified research roadmap (docs/research_improvements_2026-06.md): unbiased competing-risks/multi-state estimation, a SurvivalBoost wrapper, PoC artifact features for downstream transitions, and two new label connectors.

**Architecture:** Four independent workstreams on disjoint files, executed by parallel subagents; CLI/pyproject integration done afterwards by the orchestrator. Each workstream is TDD against the tiny-fixture conventions in `tests/`.

**Tech Stack:** lifelines (AalenJohansenFitter, CoxPHFitter), hazardous (SurvivalBoost/GradientBoostingIncidence), pandas/pyarrow, requests-style fetch connectors following `fetch/base.py`.

**Shared conventions (every workstream):**
- Use `.venv/Scripts/python.exe -m pytest` (plain pytest works; FutureWarnings are errors).
- All dates tz-aware UTC (`pd.to_datetime(..., utc=True)`).
- List columns load as `numpy.ndarray`, not list.
- Every emitted feature family needs a provenance row with an explicit `leakage_status`.
- Do NOT commit; the orchestrator reviews and commits.
- Do NOT create README files.

---

### Task W1: Competing-risks / multi-state core

**Files:**
- Create: `src/temporal_exploit/competing.py`
- Test: `tests/test_competing.py`

Input schemas (verify against `src/temporal_exploit/labels.py` before coding):
- competing-risks labels: `(cve_id, published, duration_days, event_cause, cause_code, event_observed)`, cause_code 0 == censored.
- per-signal labels: `cve_id, published` + per source `{src}_event_date`, `{src}_event_observed`, `{src}_duration_days`, `{src}_negative_duration_flag`.

- [ ] Write failing tests for `prepare_competing_frame(labels, features)`: inner-merges features on cve_id, drops rows with `duration_days <= 0`, keeps cause_code.
- [ ] Implement; run; pass.
- [ ] Write failing tests for `fit_aalen_johansen(frame) -> dict[int, AalenJohansenFitter]` (one fitter per nonzero cause) and `cif_table(fitters, horizons) -> DataFrame[cause_code, horizon, cif]`; assert CIFs in [0,1], non-decreasing in horizon, and that the sum of all-cause CIFs at a horizon <= 1 (joint estimation property).
- [ ] Implement with lifelines `AalenJohansenFitter(calculate_variance=False)`; run; pass.
- [ ] Write failing tests for `fit_cause_specific_cox(frame, cause_code, penalizer=0.1)`: event indicator is `cause_code == k` (other causes censored — valid for hazards, not probabilities; say so in the docstring).
- [ ] Implement; run; pass.
- [ ] Write failing tests for `transition_frame(per_signal, from_signal, to_signal, snapshot_date)`: rows = CVEs with from_signal observed; duration = to_date − from_date days when to-signal observed, else snapshot − from_date censored; negative durations dropped with count returned via attrs or a flag column.
- [ ] Implement; run; pass.
- [ ] Write failing tests for `cif_calibration_table(pred_risk, frame, cause_code, horizon, n_bins=10)`: per risk bin, observed = Aalen-Johansen CIF at horizon within the bin (competing-aware analog of `modeling.calibration_table`); columns `[cause_code, horizon, bin_mid, mean_pred, observed, count]`.
- [ ] Implement; run; pass.

### Task W2: SurvivalBoost wrapper

**Files:**
- Create: `src/temporal_exploit/survboost.py`
- Test: `tests/test_survboost.py`

- [ ] `pip install hazardous` into `.venv`; introspect which estimator exists (`SurvivalBoost` in newer releases, `GradientBoostingIncidence` in 0.1.0) and wrap whichever is available.
- [ ] Write failing tests (gated with `pytest.importorskip("hazardous")`) for `fit_survival_boost(frame, **params)` returning a wrapper with `feature_cols_` and `cif_at(X, horizons) -> ndarray (n, n_causes, n_horizons)` or per-cause variant; assert CIF in [0,1] and non-decreasing in horizon.
- [ ] Implement with lazy import (module imports without hazardous installed), mirroring `xgb.py`'s structure; run; pass.

### Task W3: PoC artifact features (downstream-transition-safe)

**Files:**
- Create: `src/temporal_exploit/poc_features.py`
- Test: `tests/test_poc_features.py`

poc_dates schema: `(cve_id, poc_source, poc_first_seen tz-UTC, poc_path)`.

- [ ] Write failing tests for `build_poc_features(corpus, poc_dates, top_k_exts=5)` returning one row per corpus CVE: `poc_count`, `poc_source_count`, `poc_first_lag_days` (earliest poc_first_seen − published; NaN→-1 with `poc_missing` indicator), `poc_ext_*` one-hot of top-k file extensions parsed from poc_path.
- [ ] Implement; run; pass.
- [ ] Write failing test for `poc_feature_provenance()`: every emitted family covered, `leakage_status == "transition_safe_post_poc"`, notes stating these are ONLY valid for models whose clock starts at/after the PoC event (Metasploit/Nuclei/KEV-given-PoC) — they are label leakage for the PoC endpoint itself.
- [ ] Implement; run; pass.

### Task W4: Label connectors (Exploit-DB, VulnCheck KEV)

**Files:**
- Create: `src/temporal_exploit/fetch/exploitdb.py`, `src/temporal_exploit/fetch/vulncheck.py`
- Test: `tests/test_fetch_exploitdb.py`, `tests/test_fetch_vulncheck.py`

Follow the `Connector` ABC pattern — read `fetch/base.py` and `fetch/kev.py` first. Network isolated in module-level `_fetch_*` functions, mocked in tests.

- [ ] Exploit-DB: failing tests for parsing the GitLab `files_exploits.csv` (columns include `id, file, description, date_published, verified, codes`; `codes` is a `;`-separated list containing CVE ids) into `(cve_id, exploitdb_id, exploitdb_date_published tz-UTC, exploitdb_verified int)`; one row per (cve_id, exploitdb_id); rows without a CVE code dropped.
- [ ] Implement `ExploitDbConnector` (`name = "exploitdb"`), URL `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`; run; pass.
- [ ] VulnCheck KEV: failing tests for parsing the v3 index response (`data: [{cve: [...], date_added, ...}]`, cursor-paged) into `(cve_id, vulncheck_kev_date_added tz-UTC)`; explode multi-CVE entries.
- [ ] Implement `VulncheckKevConnector` (`name = "vulncheck_kev"`, requires `token` arg, Bearer header, follows `_links.next` or cursor until exhausted); run; pass.

### Integration (orchestrator, after subagents)

- [ ] Wire `exploitdb`/`vulncheck` into `cli.fetch_command` choices.
- [ ] Add `hazardous` as a `boost` extra in pyproject.
- [ ] Full suite + ruff; commit per workstream; update `docs/progress.md` + README status.
