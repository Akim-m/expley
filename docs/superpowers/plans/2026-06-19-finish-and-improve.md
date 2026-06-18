# Finish-and-Improve Wave Implementation Plan

> **For agentic workers:** Inline TDD execution (superpowers:executing-plans).
> Shared-state files (`cli.py`, `modeling.py`, `labels.py`, `merge.py`) and
> memory-gated live-fetch ops rule out subagent-per-task isolation. Steps use
> checkbox (`- [ ]`) syntax.

**Goal:** Broaden the in-wild target with every documented live source, give it a
mixture-cure model that produces honest absolute probabilities, and surface
unbiased competing-risks CIFs as the headline.

**Architecture:** Four sequenced phases, each TDD'd + code-reviewed + committed +
pushed independently. Code changes are minimal and slot into existing dispatch
points (`EVENT_SOURCES`, `IN_WILD_SOURCES`, `MERGE_SPECS`, the `kind`-based model
dispatch). Live fetches and rebuilds are memory-gated runtime ops, not code.

**Tech Stack:** Python 3.12, uv, pandas, lifelines, sksurv, xgboost(GPU),
scipy.optimize (new use for the cure MLE), pyarrow.

## Global Constraints

- **RAM ≤ 6–8 GB, VRAM ≤ 7 GB** — `free -g`/`nvidia-smi` before every heavy step.
  In-wild training = `cox,xgb` (+`cure`); never full-corpus RSF; Metasploit mine
  watched and abortable below 2 GB free.
- **Env via uv**; interpreter `.venv/bin/python`.
- **Leakage discipline:** new sources are *labels/events*, never publication-time
  features. Exploit-DB/VulnCheck dates never enter the feature matrix.
- **tz-aware UTC** everywhere; list columns are `numpy.ndarray`.
- **Test gate:** `.venv/bin/python -m pytest -q` green (FutureWarning→error baked
  into pyproject). Commit + push after each task.
- **Immutable:** never modify `dataset_extraction-20260608T210903Z-3-002/`.
- `data/live`, `data/merged`, `artifacts/` stay gitignored.

---

## Phase 1 — Live-fetch every source, merge, rebuild

### Task 1.1: Deterministic merge for Exploit-DB + VulnCheck KEV

**Files:**
- Modify: `src/temporal_exploit/merge.py` (`MERGE_SPECS`)
- Test: `tests/test_merge.py`

**Interfaces:**
- Produces: `MERGE_SPECS["exploitdb"]`, `MERGE_SPECS["vulncheck_kev"]` consumed by
  `merge_live` (existing).

- [ ] **Step 1: Failing test** — re-fetch dedups instead of duplicating.

```python
def test_merge_dedups_vulncheck_and_exploitdb(tmp_path):
    from temporal_exploit.merge import merge_live
    handover = tmp_path / "h"; live = tmp_path / "l"; out = tmp_path / "o"
    handover.mkdir(); live.mkdir()
    # handover has no vulncheck/exploitdb counterpart; both are live-only but
    # must still dedup within the live frame on the merge key.
    import pandas as pd
    pd.DataFrame({"cve_id": ["CVE-1"], "kev_date_added": pd.to_datetime(["2022-01-01"], utc=True)}).to_parquet(handover / "kev_events.parquet")
    pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-1"],
        "vulncheck_kev_date_added": pd.to_datetime(["2022-03-01", "2022-01-15"], utc=True),
    }).to_parquet(live / "vulncheck_kev.parquet")
    merge_live(handover, live, out)
    merged = pd.read_parquet(out / "vulncheck_kev.parquet")
    assert len(merged) == 1
    assert merged.loc[0, "vulncheck_kev_date_added"] == pd.Timestamp("2022-01-15", tz="UTC")
```

- [ ] **Step 2: Run, verify FAIL** — `merge_live` copies live-only sources
  verbatim today (2 rows). Run:
  `.venv/bin/python -m pytest tests/test_merge.py::test_merge_dedups_vulncheck_and_exploitdb -v`

- [ ] **Step 3: Implement** — extend `MERGE_SPECS` and make `merge_live` apply
  specs to live-only sources too (dedup within the live frame even with no
  handover file).

```python
MERGE_SPECS = {
    "kev_events": {"key": "cve_id", "order_col": "kev_date_added", "keep": "first"},
    "cve_corpus": {"key": "cve_id", "order_col": "last_modified", "keep": "last"},
    "epss_history": {"key": ["cve_id", "date"], "order_col": None, "keep": "last"},
    "google_0day": {"key": "cve_id", "order_col": None, "keep": "last"},
    "vulncheck_kev": {"key": "cve_id", "order_col": "vulncheck_kev_date_added", "keep": "first"},
    "exploitdb": {"key": ["cve_id", "exploitdb_id"], "order_col": "exploitdb_date_published", "keep": "first"},
}
```

In the live-only passthrough loop, when a spec exists, apply
`merge_source(empty_handover, live, **spec)` (dedup) before writing, instead of
`shutil.copy2`.

- [ ] **Step 4: Run, verify PASS** + full suite green.
- [ ] **Step 5: Commit + push** — `fix: deterministic merge for exploitdb/vulncheck_kev`.

### Op 1.2: Run all live fetches + merge (memory-gated runtime, no code)

- [ ] `free -g`; ensure ≥3 GB free.
- [ ] Light sources to `data/live/`: `kev`, `epss --date <today>`, `nvd --start
  <recent> --end <today>`, `nuclei --repo`, `poc --repo`, `zeroday`, `exploitdb`.
  Each via `.venv/bin/temporal-exploit fetch --source … --live-dir data/live`.
- [ ] `vulncheck_kev`: check `VULNCHECK_API_TOKEN` in env. If present, fetch +
  inspect `date_added` for the launch spike (record it for Task 2.2). If absent,
  record **blocked: needs VULNCHECK_API_TOKEN** in the run notes — do not fake.
- [ ] `metasploit`: `free -g` first; run the mine in background with a `free -g`
  watch; abort if available RAM < 2 GB. If unsafe, record **skipped (memory)**.
- [ ] `merge --handover-dir <out> --live-dir data/live --out-dir data/merged`;
  read `merge_manifest.json`; confirm deltas. (Gitignored outputs.)

---

## Phase 2 — In-wild label broadening + Exploit-DB tooling source

### Task 2.1: Wire the two new event sources

**Files:**
- Modify: `src/temporal_exploit/cli.py` (`EVENT_SOURCES`)
- Modify: `src/temporal_exploit/labels.py` (`IN_WILD_SOURCES`)
- Test: `tests/test_labels.py`

**Interfaces:**
- Consumes: `event_frames` dict keyed by source name (existing builder contract).
- Produces: `IN_WILD_SOURCES = ("kev", "google_0day", "vulncheck_kev")`.

- [ ] **Step 1: Failing test** — VulnCheck event counts as in-wild; Exploit-DB
  counts as first-weaponization but NOT in-wild.

```python
def test_vulncheck_is_in_wild_exploitdb_is_not():
    import pandas as pd
    from temporal_exploit.labels import build_in_wild_labels, build_first_weaponization_labels
    corpus = pd.DataFrame({"cve_id": ["CVE-A", "CVE-B"],
                           "published": pd.to_datetime(["2023-01-01", "2023-01-01"], utc=True)})
    frames = {
        "vulncheck_kev": (pd.DataFrame({"cve_id": ["CVE-A"],
            "vulncheck_kev_date_added": pd.to_datetime(["2023-02-01"], utc=True)}), "vulncheck_kev_date_added"),
        "exploitdb": (pd.DataFrame({"cve_id": ["CVE-B"],
            "exploitdb_date_published": pd.to_datetime(["2023-01-10"], utc=True)}), "exploitdb_date_published"),
    }
    iw = build_in_wild_labels(corpus, frames, "2026-03-14")
    assert iw.set_index("cve_id").loc["CVE-A", "event_observed"]      # vulncheck -> in-wild
    assert not iw.set_index("cve_id").loc["CVE-B", "event_observed"]  # exploitdb -> not in-wild
    fw = build_first_weaponization_labels(corpus, frames, "2026-03-14")
    assert fw.set_index("cve_id").loc["CVE-B", "event_source"] == "exploitdb"  # exploitdb -> first-weap
```

- [ ] **Step 2: Run, verify FAIL** (`vulncheck_kev` not in `IN_WILD_SOURCES`).
- [ ] **Step 3: Implement** — `labels.IN_WILD_SOURCES = ("kev", "google_0day",
  "vulncheck_kev")`; add to `cli.EVENT_SOURCES`:

```python
"exploitdb": ("exploitdb", "exploitdb_date_published"),
"vulncheck_kev": ("vulncheck_kev", "vulncheck_kev_date_added"),
```

- [ ] **Step 4: Run, verify PASS** + full suite.
- [ ] **Step 5: Commit + push** — `feat: exploitdb (tooling) + vulncheck_kev (in-wild) event sources`.

### Task 2.2: Generalize the in-wild clock-start guard

**Files:**
- Modify: `src/temporal_exploit/cli.py` (`KEV_CATALOG_START` → `CATALOG_START`
  lookup; `train_command` in-wild filter)
- Test: `tests/test_cli.py`

**Interfaces:**
- Produces: `CATALOG_START: dict[str, str]` (`{"kev": "2021-11-03",
  "vulncheck_kev": <empirical>}`); filter rule `published >= max(start for active
  sources present in the lookup)`. Google 0-day absent → no constraint.

- [ ] **Step 1: Failing test** — filter uses the max over active catalog sources.

```python
def test_in_wild_clock_filter_uses_max_catalog_start():
    from temporal_exploit.cli import in_wild_clock_start, CATALOG_START
    # with both kev and vulncheck active, the start is the later of the two
    assert in_wild_clock_start(("kev", "vulncheck_kev", "google_0day")) == max(
        CATALOG_START["kev"], CATALOG_START["vulncheck_kev"]
    )
    # google_0day alone has no catalog artifact -> no filter (None)
    assert in_wild_clock_start(("google_0day",)) is None
```

- [ ] **Step 2: Run, verify FAIL** (`in_wild_clock_start` undefined).
- [ ] **Step 3: Implement** — add the lookup + helper; `train_command` calls
  `in_wild_clock_start(active_in_wild_sources)` instead of the hard-coded date;
  when `None`, skip the filter. Pin `vulncheck_kev` start from Op 1.2's spike
  (fallback to its known service-launch date if VulnCheck was blocked, with a
  comment).

```python
CATALOG_START = {"kev": "2021-11-03", "vulncheck_kev": "2024-01-01"}  # vulncheck pinned from fetched date_added spike

def in_wild_clock_start(active_sources) -> str | None:
    starts = [CATALOG_START[s] for s in active_sources if s in CATALOG_START]
    return max(starts) if starts else None
```

- [ ] **Step 4: Run, verify PASS** + full suite.
- [ ] **Step 5: Commit + push** — `fix: per-source in-wild catalog clock-start guard`.

### Op 2.3: Rebuild + retrain in-wild (memory-gated)

- [ ] `free -g`; `build-dataset --out-dir data/merged --artifact-dir artifacts
  --snapshot-date <today> --cutoff-date 2024-01-01 --epss-path …` (peak ~5.8 GB —
  nothing else running).
- [ ] Confirm `manifest.json` `in_wild_observed` rose vs the 1,543 baseline.
- [ ] `train --label-set in_wild --models cox,xgb --cutoff-date 2024-01-01`.
- [ ] Record c-index + CI + IPA delta vs 0.849 baseline — honestly, either way.

---

## Phase 3 — Mixture-cure model for in-wild absolute calibration

### Task 3.1: `cure.py` — parametric mixture-cure MLE

**Files:**
- Create: `src/temporal_exploit/cure.py`
- Test: `tests/test_cure.py`

**Interfaces:**
- Produces: `fit_cure(train_frame, penalizer=…) -> CureModel`; `CureModel` with
  `.feature_cols_: list[str]`, `.risk_scores(X)->np.ndarray`,
  `.survival_at(X, horizons)->np.ndarray (n,len(horizons))`,
  `.cure_fraction(X)->np.ndarray` (= `1−p(x)`).

- [ ] **Step 1: Failing test** — recover a known cure fraction; population S(t)
  plateaus above 0; P(event) monotone in t.

```python
import numpy as np, pandas as pd

def _synth_cure(n=4000, seed=0):
    rng = np.random.default_rng(seed)
    x = rng.normal(size=n)
    p_sus = 1 / (1 + np.exp(-(0.5 + 1.0 * x)))      # susceptible prob
    susceptible = rng.random(n) < p_sus
    t = rng.weibull(1.3, size=n) * 50               # latency for susceptibles
    censor = 365.0
    dur = np.where(susceptible, np.minimum(t, censor), censor)
    obs = susceptible & (t <= censor)
    return pd.DataFrame({"cve_id": np.arange(n), "published": pd.Timestamp("2020-01-01", tz="UTC"),
                         "duration_days": dur, "event_observed": obs,
                         "negative_duration_flag": False, "feat_x": x})

def test_cure_recovers_fraction_and_plateaus():
    from temporal_exploit.cure import fit_cure
    frame = _synth_cure()
    model = fit_cure(frame)
    # at the population mean (x=0) susceptible prob ~ sigmoid(0.5) ~ 0.62
    Xmean = pd.DataFrame({"feat_x": [0.0]})
    cure = float(model.cure_fraction(Xmean)[0])
    assert 0.25 < cure < 0.55                       # ~0.38 cured
    surv = model.survival_at(Xmean, [10, 100, 100000])
    assert surv[0, 0] > surv[0, 1] > surv[0, 2]     # decreasing
    assert surv[0, 2] > 0.20                         # plateaus at the cured mass, not 0
```

- [ ] **Step 2: Run, verify FAIL** (module missing).
- [ ] **Step 3: Implement** `cure.py` — standardized features; params
  `[γ0,γ (incidence), β0,β (log-scale), log_k]`; NLL with overflow-guarded
  Weibull; `scipy.optimize.minimize(method="L-BFGS-B")`; ridge on γ,β. Reuse
  `modeling._feature_columns` for the feature set. `survival_at` returns the
  population `S(t|x) = (1−p)+p·S_u`; `risk_scores` = `p·(1−S_u(max_h))`.
- [ ] **Step 4: Run, verify PASS** + full suite.
- [ ] **Step 5: Commit + push** — `feat: parametric mixture-cure model (cure.py)`.

### Task 3.2: Wire `kind="cure"` into evaluation + train CLI

**Files:**
- Modify: `src/temporal_exploit/modeling.py` (`_risk_scores`, `survival_at`)
- Modify: `src/temporal_exploit/cli.py` (`train_command` model selection +
  `--models` validation set)
- Test: `tests/test_modeling.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `CureModel` from Task 3.1.

- [ ] **Step 1: Failing test** — dispatch + end-to-end train with `cure`.

```python
def test_survival_at_dispatches_cure():
    from temporal_exploit.cure import fit_cure
    from temporal_exploit.modeling import survival_at
    frame = _synth_cure()
    model = fit_cure(frame)
    X = frame[model.feature_cols_].astype(float).head(5)
    surv = survival_at(model, X, [30, 90], "cure")
    assert surv.shape == (5, 2)
```

- [ ] **Step 2: Run, verify FAIL** (`survival_at` has no `cure` branch).
- [ ] **Step 3: Implement** — add `cure` branches to `_risk_scores`/`survival_at`
  (delegate to the model's methods, mirroring `xgb`); add `"cure"` to the
  `train_command` `unknown = set(models) - {…}` set and a `fit_cure` import +
  `fitted["cure"] = fit_cure(train)` block.
- [ ] **Step 4: Run, verify PASS** + full suite.
- [ ] **Step 5: Commit + push** — `feat: wire cure model into train + evaluation dispatch`.

### Op 3.3: Train in-wild with cure (memory-gated)

- [ ] `train --label-set in_wild --models cox,xgb,cure --cutoff-date 2024-01-01`.
- [ ] **Success gate:** IPA@90d and IPA@180d > 0 (beats train-KM null), c-index
  within Cox CI [0.805, 0.893]. Record the numbers + the calibration plot. If IPA
  stays ≤ 0, document the negative result (don't bury it).

---

## Phase 4 — CIF-based headline evaluation

### Task 4.1: Per-cause test discrimination for competing risks

**Files:**
- Modify: `src/temporal_exploit/competing.py`
- Test: `tests/test_competing.py`

**Interfaces:**
- Produces: `cause_specific_cindex(train, test, cause_code) -> float|None`
  (Harrell C of the cause-specific Cox risk on the test set; `None` if test has
  no events for the cause).

- [ ] **Step 1: Failing test** — returns a number in [0,1] for a cause with test
  events, `None` when the cause has none. (Use the existing competing fixtures.)
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `cause_specific_cindex` using
  `fit_cause_specific_cox` + lifelines `concordance_index` on the test frame's
  cause-specific (duration, indicator) restricted to that cause.
- [ ] **Step 4: Run, verify PASS** + full suite.
- [ ] **Step 5: Commit + push** — `feat: per-cause test c-index for competing risks`.

### Task 4.2: AJ-vs-independent-KM headline block

**Files:**
- Modify: `src/temporal_exploit/competing.py` (helper) +
  `src/temporal_exploit/cli.py` (`train_competing_command` emits the block)
- Test: `tests/test_competing.py`

**Interfaces:**
- Produces: `cif_vs_independent(train, horizons) -> DataFrame` with columns
  `[cause, horizon, aj_cif, independent_km, inflation]` where
  `independent_km = 1 − KM_cause(h)` (treating other causes as censored) and
  `inflation = independent_km − aj_cif ≥ 0`.

- [ ] **Step 1: Failing test** — independent-KM ≥ AJ CIF per cause/horizon
  (competing events inflate the naive estimate); `inflation ≥ 0`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** the helper; `train_competing_command` adds
  `metrics["headline_cif"] = cif_vs_independent(train, horizons).to_dict(...)`
  and `metrics["cause_specific_cox"][k]["test_c_index"] =
  cause_specific_cindex(...)`.
- [ ] **Step 4: Run, verify PASS** + full suite.
- [ ] **Step 5: Commit + push** — `feat: unbiased AJ-vs-independent CIF headline + per-cause test c-index`.

### Op 4.3: Run train-competing + verify (memory-gated)

- [ ] `train-competing --cutoff-date 2024-01-01 --snapshot-date <today>`.
- [ ] Confirm `competing_metrics.json` has `headline_cif` (inflation gaps) +
  per-cause `test_c_index`. Update README headline to cite the AJ CIF.

---

## Cross-cutting closeout (after Phase 4)

- [ ] `/code-review` over the full diff; address findings (receiving-code-review
  skill for any pushback).
- [ ] Update `docs/progress.md` (Recently landed), README (Project status + Scope
  for improvement), append a status block to `docs/audit_2026-06-12.md`.
- [ ] Final `.venv/bin/python -m pytest -q` green; commit + push the docs.

## Self-Review (run after writing)

1. **Spec coverage:** SP1→Phase1; SP2→Phase2; SP3→Phase3; SP4→Phase4; memory +
   leakage + docs → Global Constraints + closeout. ✓ No gaps.
2. **Placeholder scan:** `<empirical>`/`<today>`/`<recent>` are runtime values
   pinned during ops, not code placeholders; the one code default
   (`vulncheck_kev` start) is pinned in Task 2.2 with a fallback. ✓
3. **Type consistency:** `CureModel` surface (`feature_cols_`, `risk_scores`,
   `survival_at`, `cure_fraction`) is identical in Tasks 3.1/3.2/Op3.3;
   `in_wild_clock_start`/`CATALOG_START` identical in Task 2.2 test + impl;
   `cif_vs_independent`/`cause_specific_cindex` identical in Tasks 4.1/4.2. ✓
