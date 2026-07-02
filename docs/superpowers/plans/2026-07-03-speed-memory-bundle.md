# Speed/Memory Bundle (S1–S4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the four speed/memory workstreams of the 2026-07-03 pipeline-improvement design (spec: `docs/superpowers/specs/2026-07-03-pipeline-improvement-design.md`) with measured before/after numbers and bit-identical outputs where required.

**Architecture:** Pure refactors first (vectorized feature builders, cached landmark-EPSS loader, backtest merge hoist) — each provably output-identical; then two measured behavior changes (XGB early stopping with a usable validation split; thread-parallel hill-climb) gated on paired-delta backtests.

**Tech Stack:** pandas + pyarrow + XGBoost (CUDA) + lifelines; pytest; uv-managed `.venv`.

## Global Constraints

- Memory gates: ≤6 GB peak RSS per process, ≤7 GB VRAM. Measure with `/usr/bin/time -v`.
- No EPSS data as model features (user directive 2026-07-02); this plan touches EPSS only as pipeline plumbing.
- All dates tz-aware UTC; list columns arrive as `numpy.ndarray`.
- Use `.venv/bin/python` for everything.
- Do-not-touch list in `docs/progress.md` stands (EPSS streaming internals, fused scan, date pushdown, earliest-event hoist, vectorized KM/NLL/Breslow, int8 downcast, caps/batching).
- **After every task: append a row to `docs/improvement_log_2026-07-02.md` §"Changes landed"** with what/why/before→after (user directive 2026-07-03), then commit.
- Baselines to beat (measured 2026-07-02/03): build fast 21.3 s / 858 MB; build+EPSS 4 m 13 s / 1.21 GB; 15-origin backtest 38.5 s / 1.03 GB; suite 1 m 47 s / 613 MB.
- Pre-change reference outputs for identity checks (already on disk):
  - `<SCRATCH>/bench_baseline/` — fast build artifacts
  - `<SCRATCH>/bench_epss/` — EPSS build artifacts
  - `<SCRATCH>/bench_backtest/` — 15-origin backtest report
  where `<SCRATCH>` = `/tmp/claude-0/-home-akim-Coding-Expl/b9541518-220c-4886-8d7d-6c4774dba6d1/scratchpad`.

---

### Task 1: Shared vectorized CVSS-vector parse

The same vector string is parsed twice (`features.py:_vector_levels` via `.map`, `incentive_features.py:_parse_cvss_vector` via `.map` + 8 more `.map` passes). Replace with one vectorized `str.extract` parse shared by both builders.

**Files:**
- Modify: `src/temporal_exploit/features.py`
- Modify: `src/temporal_exploit/incentive_features.py`
- Modify: `src/temporal_exploit/cli.py` (build_dataset_command: parse once, pass to both builders)
- Test: `tests/test_cvss_parse.py` (new)

**Interfaces:**
- Produces: `features.parse_cvss_vectors(vec: pd.Series) -> pd.DataFrame` — columns `AV,AC,PR,UI,S,C,I,A`, object dtype, `None` where absent/malformed; **last occurrence wins** on duplicate keys (matches the dict-overwrite semantics of both old parsers).
- `build_publication_features(corpus, top_k_cwes=20, parsed_vectors=None)` and `build_incentive_features(corpus, parsed_vectors=None)` — optional pre-parsed frame; `None` → parse internally (back-compat).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cvss_parse.py
import numpy as np
import pandas as pd

from temporal_exploit.features import build_publication_features, parse_cvss_vectors
from temporal_exploit.incentive_features import build_incentive_features


def _corpus():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
        "published": pd.to_datetime(["2024-01-01"] * 4, utc=True),
        "cvss_v3_base": [9.8, 5.0, None, 7.5],
        "cvss_v3_severity": ["CRITICAL", "MEDIUM", None, "HIGH"],
        "cvss_v3_vector": [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N",
            None,                                   # missing vector
            "AV:P/AV:N/AC:L",                       # malformed + duplicate key
        ],
        "cwe_ids": [np.array(["CWE-79"]), np.array([]), None, np.array(["CWE-89", "CWE-79"])],
        "vendors": [np.array(["a"]), np.array([]), None, np.array(["b", "c"])],
        "products": [np.array(["p"]), np.array([]), None, np.array(["q"])],
    })


def test_parse_cvss_vectors_matches_dict_semantics():
    parsed = parse_cvss_vectors(_corpus()["cvss_v3_vector"])
    assert list(parsed.columns) == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert parsed.loc[0, "AV"] == "N" and parsed.loc[0, "S"] == "U"
    assert parsed.loc[1, "UI"] == "R"
    assert parsed.loc[2].isna().all() or all(v is None for v in parsed.loc[2])
    assert parsed.loc[3, "AV"] == "N"          # duplicate key: LAST wins
    assert parsed.loc[3, "PR"] is None          # absent key -> None
    # 'S' must not match the 'SS' inside the 'CVSS:3.1' prefix
    assert parsed.loc[0, "S"] == "U" and parsed.loc[1, "S"] == "C"


def test_builders_identical_with_and_without_preparse():
    corpus = _corpus()
    parsed = parse_cvss_vectors(corpus["cvss_v3_vector"])
    pd.testing.assert_frame_equal(
        build_publication_features(corpus),
        build_publication_features(corpus, parsed_vectors=parsed),
    )
    pd.testing.assert_frame_equal(
        build_incentive_features(corpus),
        build_incentive_features(corpus, parsed_vectors=parsed),
    )


def test_incentive_values_unchanged():
    feats = build_incentive_features(_corpus())
    assert feats.loc[0, "incentive_wormable"] == 1
    assert feats.loc[1, "incentive_wormable"] == 0
    assert feats.loc[2, "incentive_cvss_vector_missing"] == 1
    assert feats.loc[3, "incentive_network"] == 1   # AV last-occurrence = N
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_cvss_parse.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_cvss_vectors'`

- [ ] **Step 3: Implement**

In `src/temporal_exploit/features.py`, replace `_vector_levels` usage (keep the function for back-compat of any external callers; the builder no longer uses it):

```python
_CVSS_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_cvss_vectors(vec: pd.Series) -> pd.DataFrame:
    """Vectorized CVSS v3 vector parse: one str.extract pass per metric instead of
    a Python dict parse per row. Object dtype with None for absent/malformed
    (so `parsed[k] == "N"` is elementwise-False on missing, matching the old
    dict.get semantics); last occurrence wins on duplicate keys, matching the
    dict-overwrite behavior of the old per-row parsers."""
    s = vec.astype("string")
    out = pd.DataFrame(index=vec.index)
    for key in _CVSS_METRICS:
        # greedy ^.* -> the LAST (?:^|/)KEY: occurrence; [^/]+ -> its value
        col = s.str.extract(rf"^.*(?:^|/){key}:([^/]+)", expand=False)
        out[key] = col.astype(object).where(col.notna(), None)
    return out
```

In `build_publication_features`, change the signature to
`def build_publication_features(corpus: pd.DataFrame, top_k_cwes: int = 20, parsed_vectors: pd.DataFrame | None = None) -> pd.DataFrame:`
and replace the vector block (old lines 44-51) with:

```python
    if "cvss_v3_vector" in corpus.columns:
        parsed = (
            parsed_vectors
            if parsed_vectors is not None
            else parse_cvss_vectors(corpus["cvss_v3_vector"])
        )
        for field, prefix in _VECTOR_FIELDS.items():
            col = parsed[field]
            seen = sorted({v for v in col if v is not None})
            for value in seen:
                features[f"cvss_{prefix}_{value}"] = (col == value).astype(int)
```

In `src/temporal_exploit/incentive_features.py`, change the signature to
`def build_incentive_features(corpus: pd.DataFrame, parsed_vectors: pd.DataFrame | None = None) -> pd.DataFrame:`
and replace the parse block (old lines 38-44) with:

```python
    if parsed_vectors is not None:
        parsed = parsed_vectors
    else:
        from temporal_exploit.features import parse_cvss_vectors

        parsed = parse_cvss_vectors(vec)

    def metric(key):
        return parsed[key]

    av, ac, pr, ui, scope = metric("AV"), metric("AC"), metric("PR"), metric("UI"), metric("S")
    high_impact = (metric("C") == "H") | (metric("I") == "H") | (metric("A") == "H")
```

(the downstream flag lines are unchanged — object-dtype `== "N"` comparisons behave exactly as before).

In `src/temporal_exploit/cli.py` `build_dataset_command`, where features are built (around line 170):

```python
    from temporal_exploit.features import parse_cvss_vectors

    parsed_vectors = (
        parse_cvss_vectors(corpus["cvss_v3_vector"])
        if "cvss_v3_vector" in corpus.columns
        else None
    )
    features = build_publication_features(corpus, parsed_vectors=parsed_vectors)
    ...
    features = features.merge(
        build_incentive_features(corpus, parsed_vectors=parsed_vectors), on="cve_id", how="left"
    )
    del parsed_vectors
```

- [ ] **Step 4: Run the new tests, then the full suite**

Run: `.venv/bin/python -m pytest tests/test_cvss_parse.py -v` → PASS
Run: `.venv/bin/python -m pytest -q` → all pass (334+ passed)

- [ ] **Step 5: Improvement-log entry + commit**

Append to §"Changes landed" in `docs/improvement_log_2026-07-02.md`:
`| Shared vectorized CVSS parse (features/incentive/cli) | Same vector string was parsed twice via per-row .map; one str.extract pass feeds both builders | build wall-clock: (fill after Task 7 rebuild); outputs bit-identical |`

```bash
git add src/temporal_exploit/features.py src/temporal_exploit/incentive_features.py src/temporal_exploit/cli.py tests/test_cvss_parse.py docs/improvement_log_2026-07-02.md
git commit -m "perf: single vectorized CVSS-vector parse shared by feature builders"
```

---

### Task 2: Vectorized top-k CWE membership

`features.py:58-64` builds per-row Python sets then runs one `.map` pass per top-k CWE (20 passes × 360k rows). Replace with one explode + crosstab.

**Files:**
- Modify: `src/temporal_exploit/features.py:53-64`
- Test: `tests/test_cvss_parse.py` (extend)

**Interfaces:**
- No API change; `build_publication_features` output must be bit-identical (same columns, same order, same dtypes).

- [ ] **Step 1: Write the failing test** (characterization: current behavior, then refactor must keep it green)

```python
def test_cwe_topk_columns_and_values():
    corpus = _corpus()
    feats = build_publication_features(corpus, top_k_cwes=2)
    # frequency ranking with (-count, name) tie-break: CWE-79 (2) then CWE-89 (1)
    cwe_cols = [c for c in feats.columns if c.startswith("cwe_")]
    assert cwe_cols == ["cwe_CWE-79", "cwe_CWE-89"]
    assert feats["cwe_CWE-79"].tolist() == [1, 0, 0, 1]
    assert feats["cwe_CWE-89"].tolist() == [0, 0, 0, 1]
    # duplicate CWE within one CVE counts once (set semantics)
    dup = corpus.copy()
    dup.at[0, "cwe_ids"] = np.array(["CWE-79", "CWE-79"])
    feats_dup = build_publication_features(dup, top_k_cwes=2)
    assert feats_dup["cwe_CWE-79"].tolist() == [1, 0, 0, 1]
```

- [ ] **Step 2: Run** — `.venv/bin/python -m pytest tests/test_cvss_parse.py::test_cwe_topk_columns_and_values -v` → PASS against the OLD code (characterization baseline). Commit nothing yet; now refactor.

- [ ] **Step 3: Replace the implementation** (old lines 58-64):

```python
    # one explode instead of top_k .map membership passes over the corpus
    cwe_lists = corpus["cwe_ids"].map(
        lambda v: sorted(set(v)) if isinstance(v, (list, tuple, np.ndarray)) else []
    )
    exploded = pd.DataFrame(
        {"cve_id": corpus["cve_id"], "cwe": cwe_lists}
    ).explode("cwe").dropna(subset=["cwe"])
    freq = exploded["cwe"].value_counts()
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))
    top = [cwe for cwe, _ in ranked[:top_k_cwes]]
    if top:
        member = exploded[exploded["cwe"].isin(top)]
        pivot = pd.crosstab(member["cve_id"], member["cwe"]).clip(upper=1)
        for cwe in top:
            col = pivot[cwe] if cwe in pivot.columns else None
            features[f"cwe_{cwe}"] = (
                features["cve_id"].map(col).fillna(0).astype(int) if col is not None else 0
            )
```

Keep `has_weakness` / `weakness_count` / `vendor_count` / `product_count` as they are (single cheap passes). Delete the now-unused `cwe_sets` block.

- [ ] **Step 4: Run tests** — `.venv/bin/python -m pytest tests/test_cvss_parse.py -v && .venv/bin/python -m pytest -q` → all PASS

- [ ] **Step 5: Improvement-log entry + commit**

```bash
git add src/temporal_exploit/features.py tests/test_cvss_parse.py docs/improvement_log_2026-07-02.md
git commit -m "perf: explode+crosstab CWE membership (1 pass, was top_k .map passes)"
```

---

### Task 3: Cached landmark-EPSS loader; repoint the two re-streaming scripts

`scripts/operating_points.py:48` and `scripts/inwild_epss_ablation_landmark.py:55` re-stream the 375M-row file (~4 min each) although build-dataset persists `landmark_features_{L}d.parquet`. Add a guarded loader; fall back to streaming when the artifact is missing, stale (missing trajectory columns — the 2026-06-12 artifacts predate them), snapshot-mismatched, or corpus-incomplete.

**Files:**
- Modify: `src/temporal_exploit/landmark.py` (add loader at end of file)
- Modify: `scripts/operating_points.py:47-48`
- Modify: `scripts/inwild_epss_ablation_landmark.py:54-55`
- Test: `tests/test_landmark_cache.py` (new)

**Interfaces:**
- Produces: `landmark.load_epss_at_landmark(corpus, epss_path, landmark_days, snapshot_date, artifact_dir=None, batch_size=262_144) -> pd.DataFrame` — same columns as `build_epss_at_landmark` (`cve_id` + `_LANDMARK_EPSS_COLUMNS`), rows aligned to `corpus["cve_id"]` order.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_landmark_cache.py
import json

import numpy as np
import pandas as pd
import pytest

from temporal_exploit.landmark import _LANDMARK_EPSS_COLUMNS, load_epss_at_landmark


def _corpus():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2"],
        "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
    })


def _fake_bundle(corpus):
    out = corpus[["cve_id"]].copy()
    for c in _LANDMARK_EPSS_COLUMNS:
        out[c] = 0.5
    return out


def _write_artifacts(tmp_path, corpus, snapshot, columns=None):
    bundle = _fake_bundle(corpus)
    if columns is not None:
        bundle = bundle[columns]
    bundle.to_parquet(tmp_path / "landmark_features_30d.parquet", index=False)
    (tmp_path / "manifest.json").write_text(json.dumps({"snapshot_date": snapshot}))


def test_cache_hit_reads_parquet_not_stream(tmp_path):
    corpus = _corpus()
    _write_artifacts(tmp_path, corpus, "2026-03-14")
    got = load_epss_at_landmark(
        corpus, epss_path="/nonexistent.parquet", landmark_days=30,
        snapshot_date="2026-03-14", artifact_dir=tmp_path,
    )  # streaming would raise on the nonexistent path -> cache must have been used
    assert list(got.columns) == ["cve_id", *_LANDMARK_EPSS_COLUMNS]
    assert got["cve_id"].tolist() == corpus["cve_id"].tolist()


@pytest.mark.parametrize("break_it", ["snapshot", "columns", "coverage", "missing"])
def test_cache_falls_back_when_invalid(tmp_path, break_it):
    corpus = _corpus()
    if break_it == "snapshot":
        _write_artifacts(tmp_path, corpus, "2020-01-01")
    elif break_it == "columns":  # stale pre-trajectory artifact (2026-06-12 shape)
        _write_artifacts(tmp_path, corpus, "2026-03-14",
                         columns=["cve_id", "epss_at_landmark"])
    elif break_it == "coverage":
        _write_artifacts(tmp_path, corpus.iloc[:1], "2026-03-14")
    # "missing": no files at all
    with pytest.raises(Exception):  # falls back to streaming -> bad path raises
        load_epss_at_landmark(
            corpus, epss_path="/nonexistent.parquet", landmark_days=30,
            snapshot_date="2026-03-14", artifact_dir=tmp_path,
        )
```

- [ ] **Step 2: Run** — `.venv/bin/python -m pytest tests/test_landmark_cache.py -v` → FAIL (`ImportError: load_epss_at_landmark`)

- [ ] **Step 3: Implement** (append to `landmark.py`; add `import json` + `from pathlib import Path` at top):

```python
def load_epss_at_landmark(
    corpus: pd.DataFrame,
    epss_path: str,
    landmark_days: int,
    snapshot_date: str | None = None,
    artifact_dir=None,
    batch_size: int = 262_144,
) -> pd.DataFrame:
    """Landmark EPSS trajectory from the persisted build artifact when valid,
    else the streamed build. Validity: file exists, manifest snapshot matches,
    all trajectory columns present (pre-2026-06 artifacts lack them), and the
    artifact covers every corpus cve_id. Returns rows in corpus order — the
    same contract as build_epss_at_landmark."""
    if artifact_dir is not None:
        path = Path(artifact_dir) / f"landmark_features_{landmark_days}d.parquet"
        manifest_path = Path(artifact_dir) / "manifest.json"
        if path.exists() and manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            if manifest.get("snapshot_date") == snapshot_date:
                import pyarrow.parquet as pq

                have = set(pq.ParquetFile(path).schema_arrow.names)
                need = {"cve_id", *_LANDMARK_EPSS_COLUMNS}
                if need <= have:
                    lm = pd.read_parquet(path, columns=["cve_id", *_LANDMARK_EPSS_COLUMNS])
                    aligned = corpus[["cve_id"]].merge(lm, on="cve_id", how="left")
                    if not aligned[_LANDMARK_EPSS_COLUMNS[0]].isna().any():
                        return aligned
    return build_epss_at_landmark(
        corpus, epss_path, landmark_days, snapshot_date=snapshot_date, batch_size=batch_size
    )
```

- [ ] **Step 4: Repoint the scripts**

`scripts/operating_points.py` — replace line 48:

```python
from temporal_exploit.landmark import load_epss_at_landmark

print(f"loading EPSS landmark trajectory for L={LANDMARKS} (cache: artifacts/) ...", flush=True)
epss = {
    L: load_epss_at_landmark(corpus, EPSS_PATH, L, snapshot_date=SNAPSHOT, artifact_dir="artifacts")
    for L in LANDMARKS
}
```

(drop the now-unused `build_epss_features` import). `scripts/inwild_epss_ablation_landmark.py` — replace line 55:

```python
from temporal_exploit.landmark import load_epss_at_landmark

lm_epss = load_epss_at_landmark(corpus, EPSS_PATH, LANDMARK, snapshot_date=SNAPSHOT, artifact_dir="artifacts")
```

Note: until Task 7 refreshes `artifacts/`, the stale 2026-06-12 files fail the
column guard and the scripts stream exactly as before — behavior is unchanged,
which is the point of the guard.

- [ ] **Step 5: Run tests** — `.venv/bin/python -m pytest tests/test_landmark_cache.py -v && .venv/bin/python -m pytest -q` → PASS

- [ ] **Step 6: Improvement-log entry + commit**

```bash
git add src/temporal_exploit/landmark.py scripts/operating_points.py scripts/inwild_epss_ablation_landmark.py tests/test_landmark_cache.py docs/improvement_log_2026-07-02.md
git commit -m "perf: cached landmark-EPSS loader; scripts stop re-streaming the 375M-row file"
```

---

### Task 4: Hoist test-frame prepare + feature validation out of the backtest loop

`backtest.py:219-239` runs `prepare_modeling_frame` (merge + NaN scan + downcast) twice per origin. The test side re-prepares disjoint slices of the SAME `final_labels`; prepare once, mask per origin. The features NaN-scan repeats identically every call; validate once.

**Files:**
- Modify: `src/temporal_exploit/backtest.py:213-239`
- Modify: `src/temporal_exploit/modeling.py:37-66` (`prepare_modeling_frame` gains `features_validated: bool = False`)
- Test: `tests/test_backtest_hoist.py` (new)

**Interfaces:**
- `prepare_modeling_frame(labels, features, recover_negative_duration=False, features_validated=False)` — when `features_validated=True`, skip the per-call NaN scan (caller ran `validate_feature_matrix`).
- Produces: `modeling.validate_feature_matrix(features) -> None` (raises `ValueError` naming NaN columns — same message contract as the in-loop check).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_backtest_hoist.py
import numpy as np
import pandas as pd
import pytest

from temporal_exploit.modeling import prepare_modeling_frame, validate_feature_matrix


def _labels():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
        "published": pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01"], utc=True),
        "duration_days": [10.0, 20.0, 30.0],
        "event_observed": [1, 0, 1],
        "negative_duration_flag": [False, False, False],
    })


def _features(nan=False):
    f = pd.DataFrame({"cve_id": ["CVE-1", "CVE-2", "CVE-3"], "x": [1.0, 2.0, 3.0]})
    if nan:
        f.loc[1, "x"] = np.nan
    return f


def test_validate_feature_matrix_names_culprit():
    validate_feature_matrix(_features())          # clean -> no raise
    with pytest.raises(ValueError, match="x"):
        validate_feature_matrix(_features(nan=True))


def test_prepared_frame_identical_with_skip_flag():
    pd.testing.assert_frame_equal(
        prepare_modeling_frame(_labels(), _features()),
        prepare_modeling_frame(_labels(), _features(), features_validated=True),
    )


def test_skip_flag_does_not_mask_label_side_guarantees():
    # the flag only skips the FEATURE NaN scan; merge/filter/downcast unchanged
    out = prepare_modeling_frame(_labels(), _features(), features_validated=True)
    assert list(out["cve_id"]) == ["CVE-1", "CVE-2", "CVE-3"]
    assert out["duration_days"].tolist() == [10.0, 20.0, 30.0]
```

- [ ] **Step 2: Run** — `.venv/bin/python -m pytest tests/test_backtest_hoist.py -v` → FAIL (`ImportError: validate_feature_matrix`)

- [ ] **Step 3: Implement in `modeling.py`**

```python
def validate_feature_matrix(features: pd.DataFrame) -> None:
    """One-shot NaN guard over the feature matrix, hoistable out of per-origin
    loops: equivalent to prepare_modeling_frame's per-call scan because an inner
    merge cannot introduce NaN into feature columns."""
    nan_cols = [c for c in features.columns if c not in META_COLS and features[c].isna().any()]
    if nan_cols:
        raise ValueError(
            f"NaN in feature columns {nan_cols[:10]} - a feature builder emitted "
            "NaN; models require complete features (fill/flag upstream)"
        )
```

In `prepare_modeling_frame`, wrap the existing NaN scan (lines 60-65):

```python
    if not features_validated:
        nan_cols = [c for c in out.columns if c not in META_COLS and out[c].isna().any()]
        if nan_cols:
            raise ValueError(
                f"NaN in feature columns {nan_cols[:10]} - a feature builder emitted "
                "NaN; models require complete features (fill/flag upstream)"
            )
```

- [ ] **Step 4: Hoist in `backtest.py`** — in `rolling_origin_backtest`, after `final_labels`/`final_pub` (line 216):

```python
    from temporal_exploit.modeling import validate_feature_matrix

    validate_feature_matrix(features)
    # prepare the FINAL-snapshot frame once; per-origin test sets are disjoint
    # pub-window slices of it (filter-then-prepare == prepare-then-filter for an
    # inner cve_id merge + row filters, verified by the identity check in the
    # improvement log). Train frames still prepare per origin: their labels are
    # re-finalized as-of each origin.
    final_frame = prepare_modeling_frame(
        final_labels, features, recover_negative_duration=recover_negative_duration,
        features_validated=True,
    )
    final_frame_pub = pd.to_datetime(final_frame["published"], utc=True)
```

Replace the per-origin test-side block (lines 234-239):

```python
        test_mask = (final_frame_pub >= t) & (final_frame_pub < t_next)
        if cstart is not None:
            test_mask &= final_frame_pub >= cstart
        test_frame = final_frame[test_mask].reset_index(drop=True)
```

and pass `features_validated=True` to the remaining train-side `prepare_modeling_frame` call.

- [ ] **Step 5: Identity + speed check against the recorded baseline**

```bash
.venv/bin/python -m pytest -q   # suite green
/usr/bin/time -v .venv/bin/python -m temporal_exploit.cli backtest \
  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \
  --artifact-dir artifacts --report-dir <SCRATCH>/bench_backtest_after \
  --snapshot-date 2026-03-14 --start 2022-01-01 --model xgb --label-set in_wild
diff <(python3 -m json.tool <SCRATCH>/bench_backtest/*.json) \
     <(python3 -m json.tool <SCRATCH>/bench_backtest_after/*.json)
```

Expected: empty diff (identical report); wall-clock ≤ baseline 38.5 s; RSS ≤ 1.03 GB.

- [ ] **Step 6: Improvement-log entry (with the measured numbers) + commit**

```bash
git add src/temporal_exploit/backtest.py src/temporal_exploit/modeling.py tests/test_backtest_hoist.py docs/improvement_log_2026-07-02.md
git commit -m "perf: hoist test-frame prepare + feature validation out of the backtest origin loop"
```

---

### Task 5: XGB early stopping with a random event-stratified validation split

The tail split is documented to underfit (xgb.py:82-95: stops at iter 57/500, c-index 0.607→0.537) because the train tail is censoring-dominated. Add `validation="random"`: event-stratified 10% split — temporally safe inside a backtest origin because every train row predates the origin and the split only picks the boosting-round count. Plumb `model_kwargs` through the backtest so scripts can enable it. Adoption is gated on a measured A/B.

**Files:**
- Modify: `src/temporal_exploit/xgb.py:55-97`
- Modify: `src/temporal_exploit/backtest.py` (`rolling_origin_backtest(..., model_kwargs=None)`, `_fit(model, frame, model_kwargs)`)
- Test: `tests/test_xgb_earlystop.py` (new)

**Interfaces:**
- `fit_xgb_aft(..., early_stopping_rounds=None, validation="tail")` — `"tail"` preserves today's exact behavior; `"random"` = seeded event-stratified 10%.
- `rolling_origin_backtest(..., model_kwargs: dict | None = None)` — forwarded to the model fitter (xgb path only; other fitters raise TypeError on unknown kwargs, which is the loud-fail we want).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_xgb_earlystop.py
import numpy as np
import pandas as pd
import pytest

pytest.importorskip("xgboost")
from temporal_exploit.xgb import fit_xgb_aft


def _frame(n=300, seed=0):
    rng = np.random.default_rng(seed)
    x = rng.normal(size=n)
    event = rng.random(n) < 0.3
    dur = np.where(event, np.exp(2 + 0.8 * x + rng.normal(scale=0.3, size=n)), 400.0)
    return pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(n)],
        "published": pd.to_datetime(["2024-01-01"] * n, utc=True),
        "duration_days": dur.clip(min=1.0),
        "event_observed": event.astype(int),
        "negative_duration_flag": False,
        "x": x, "noise": rng.normal(size=n),
    })


def test_random_validation_early_stops_and_predicts():
    m = fit_xgb_aft(_frame(), num_rounds=400, early_stopping_rounds=20, validation="random")
    assert m.booster.best_iteration is not None
    assert m.booster.best_iteration < 399          # actually stopped
    risk = m.risk_scores(_frame(seed=1))
    assert np.isfinite(risk).all()


def test_random_split_is_seeded_deterministic():
    a = fit_xgb_aft(_frame(), num_rounds=50, early_stopping_rounds=10, validation="random", seed=7)
    b = fit_xgb_aft(_frame(), num_rounds=50, early_stopping_rounds=10, validation="random", seed=7)
    assert a.booster.best_iteration == b.booster.best_iteration


def test_unknown_validation_mode_raises():
    with pytest.raises(ValueError, match="validation"):
        fit_xgb_aft(_frame(), early_stopping_rounds=10, validation="bogus")
```

- [ ] **Step 2: Run** — `.venv/bin/python -m pytest tests/test_xgb_earlystop.py -v` → FAIL (`TypeError: unexpected keyword 'validation'`)

- [ ] **Step 3: Implement in `xgb.py`** — signature gains `validation: str = "tail"`; replace the split block (lines 78-95):

```python
    if early_stopping_rounds and len(train_frame) >= 100:
        if validation == "tail":
            # documented to stop too early on the real corpus (tail is mostly
            # censored: iter 57/500, c-index 0.607 -> 0.537); kept for back-compat.
            ordered = (
                train_frame.sort_values("published")
                if "published" in train_frame.columns
                else train_frame
            )
            split = int(len(ordered) * 0.9)
            fit_frame, val_frame = ordered.iloc[:split], ordered.iloc[split:]
        elif validation == "random":
            # event-stratified 10%: keeps the val event rate representative, so
            # aft-nloglik on it tracks fit quality instead of censoring mass.
            # Temporally safe under a rolling origin: all train rows predate the
            # origin; the split only selects the boosting-round count.
            rng = np.random.default_rng(seed)
            ev = train_frame["event_observed"].to_numpy(bool)
            idx = np.arange(len(train_frame))
            val_idx = np.concatenate([
                rng.choice(idx[ev], size=max(1, int(round(ev.sum() * 0.1))), replace=False)
                if ev.any() else np.array([], dtype=int),
                rng.choice(idx[~ev], size=int(round((~ev).sum() * 0.1)), replace=False)
                if (~ev).any() else np.array([], dtype=int),
            ])
            val_mask = np.zeros(len(train_frame), dtype=bool)
            val_mask[val_idx] = True
            fit_frame, val_frame = train_frame[~val_mask], train_frame[val_mask]
        else:
            raise ValueError(f"unknown validation mode {validation!r}; use 'tail' or 'random'")
        fit_kw = {
            "evals": [(_aft_dmatrix(xgb, val_frame, cols), "val")],
            "early_stopping_rounds": early_stopping_rounds,
            "verbose_eval": False,
        }
```

- [ ] **Step 4: Plumb `model_kwargs` in `backtest.py`**

```python
def _fit(model: str, train_frame: pd.DataFrame, model_kwargs: dict | None = None):
    kw = model_kwargs or {}
    if model == "cox":
        return fit_cox(train_frame, **kw)
    ...
    if model == "xgb":
        from temporal_exploit.xgb import fit_xgb_aft

        return fit_xgb_aft(train_frame, **kw)
    ...
```

`rolling_origin_backtest(..., model_kwargs: dict | None = None)`; the call site becomes `fitted = _fit(model, train_frame, model_kwargs)`.

- [ ] **Step 5: Run tests** — `.venv/bin/python -m pytest tests/test_xgb_earlystop.py -v && .venv/bin/python -m pytest -q` → PASS

- [ ] **Step 6: Measured A/B (adoption gate)** — script `scripts/xgb_earlystop_ab.py`:

```python
"""A/B: xgb AFT default (500 rounds, no early stop) vs early_stopping_rounds=50
with the random event-stratified split, on the standard 15-origin in-wild
backtest. Adoption gate: paired AUC@30/@90 deltas whose CI does not sit below 0,
plus measured wall-clock. Writes artifacts/xgb_earlystop_ab.json."""
import json, time
from pathlib import Path
import pandas as pd
from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAPSHOT, START = "2026-03-14", "2022-01-01"
corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:
        continue
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
features = pd.read_parquet("artifacts/publication_features.parquet")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))

def run(tag, model_kwargs):
    t0 = time.perf_counter()
    res = rolling_origin_backtest(
        corpus, event_frames, features, SNAPSHOT, origins, model="xgb",
        label_set="in_wild", clock_start=clock_start, model_kwargs=model_kwargs,
    )
    res["wall_s"] = round(time.perf_counter() - t0, 1)
    print(tag, "wall_s:", res["wall_s"], flush=True)
    return res

base = run("baseline", None)
fast = run("earlystop", {"early_stopping_rounds": 50, "validation": "random"})
out = {
    "wall_s": {"baseline": base["wall_s"], "earlystop": fast["wall_s"]},
    "deltas_earlystop_minus_base": {
        f"auc_{h}": paired_origin_deltas(fast, base, "horizon_auc", h) for h in (30, 90)
    },
}
Path("artifacts/xgb_earlystop_ab.json").write_text(json.dumps(out, indent=2))
print(json.dumps(out["deltas_earlystop_minus_base"], indent=2))
```

Run: `/usr/bin/time -v .venv/bin/python scripts/xgb_earlystop_ab.py`
Decision rule: adopt (`early_stopping_rounds=50, validation="random"` becomes the recommended backtest/hill-climb config, documented in the improvement log) only if both AUC deltas' CI95 upper bounds are ≥ 0 (not significantly worse) AND wall-clock drops. Otherwise record the negative result and keep defaults.

- [ ] **Step 7: Improvement-log entry (A/B numbers, adopt/reject decision) + commit**

```bash
git add src/temporal_exploit/xgb.py src/temporal_exploit/backtest.py tests/test_xgb_earlystop.py scripts/xgb_earlystop_ab.py artifacts/xgb_earlystop_ab.json docs/improvement_log_2026-07-02.md
git commit -m "feat(xgb): random event-stratified early-stop validation + measured A/B"
```

---

### Task 6: Thread-parallel hill-climb candidate evaluation

`hillclimb.py:99-134` evaluates each round's candidates serially; each evaluation is a full backtest. Threads (not processes): the frames are shared read-only (zero copy — a process pool would multiply the ~1 GB working set per worker toward the 6 GB gate), and the hot loop is xgboost training, which releases the GIL.

**Files:**
- Modify: `src/temporal_exploit/hillclimb.py:77-134`
- Modify: `scripts/beat_epss_hillclimb.py` (pass `n_workers=2`)
- Test: `tests/test_hillclimb_parallel.py` (new)

**Interfaces:**
- `greedy_forward_select(candidate_groups, incumbent_groups, evaluate, paired_delta, max_rounds=None, n_workers=1)` — `n_workers=1` is today's exact serial path; `>1` evaluates a round's candidates concurrently. Trial log order and selection are deterministic (submission order preserved).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hillclimb_parallel.py
import threading

from temporal_exploit.hillclimb import greedy_forward_select


def _fake_world():
    # deterministic evaluate/delta: group value = its length; 'ccc' wins round 1
    def evaluate(groups):
        return {"score": sum(len(g) for g in groups)}

    def paired_delta(challenger, incumbent):
        d = challenger["score"] - incumbent["score"]
        return {"mean_delta": float(d), "ci95": [d - 0.5, d + 0.5], "win_frac": 1.0}

    return evaluate, paired_delta


def test_parallel_matches_serial_selection():
    evaluate, paired_delta = _fake_world()
    serial = greedy_forward_select(["a", "bb", "ccc"], [], evaluate, paired_delta)
    parallel = greedy_forward_select(["a", "bb", "ccc"], [], evaluate, paired_delta, n_workers=3)
    assert parallel["accepted"] == serial["accepted"] == ["ccc", "bb", "a"]
    assert parallel["n_rounds"] == serial["n_rounds"]
    assert [t["added"] for t in parallel["trials"]] == [t["added"] for t in serial["trials"]]


def test_parallel_actually_runs_concurrently():
    evaluate, paired_delta = _fake_world()
    seen = set()

    def spying_evaluate(groups):
        seen.add(threading.current_thread().name)
        return evaluate(groups)

    greedy_forward_select(["a", "bb", "ccc"], [], spying_evaluate, paired_delta, n_workers=3)
    assert len(seen) > 1   # more than one worker thread touched evaluate
```

- [ ] **Step 2: Run** — `.venv/bin/python -m pytest tests/test_hillclimb_parallel.py -v` → FAIL (`TypeError: unexpected keyword 'n_workers'`)

- [ ] **Step 3: Implement** — in `greedy_forward_select`, replace the inner `for g in remaining:` loop:

```python
        if n_workers > 1 and len(remaining) > 1:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=min(n_workers, len(remaining))) as pool:
                results = list(pool.map(lambda g: evaluate(incumbent + [g]), remaining))
        else:
            results = [evaluate(incumbent + [g]) for g in remaining]
        for g, result in zip(remaining, results):
            delta = paired_delta(result, incumbent_result)
            sig = is_significant_gain(delta)
            trials.append({
                "round": rounds, "incumbent": list(incumbent), "added": g,
                "mean_delta": delta.get("mean_delta"), "ci95": delta.get("ci95"),
                "win_frac": delta.get("win_frac"), "accepted": False, "significant": sig,
            })
            if sig and (best is None or delta["mean_delta"] > best[2]["mean_delta"]):
                best = (g, result, delta)
```

(signature gains `n_workers: int = 1`; docstring notes threads-not-processes and why). In `scripts/beat_epss_hillclimb.py`, pass `n_workers=2` at the `greedy_forward_select` call site with the comment `# 2 threads: xgboost releases the GIL; frames shared zero-copy (process pool would multiply RSS)`.

- [ ] **Step 4: Run tests** — `.venv/bin/python -m pytest tests/test_hillclimb_parallel.py -v && .venv/bin/python -m pytest -q` → PASS

- [ ] **Step 5: Measure** — time one 2-candidate round via the A/B pattern (reuse `scripts/beat_epss_hillclimb.py` with `max_rounds=1` if it exposes it, else a 3-line driver in the scratchpad); record wall-clock serial vs `n_workers=2` and `/usr/bin/time -v` peak RSS (gate: <6 GB) + `nvidia-smi --query-gpu=memory.used --format=csv` during the run (gate: <7 GB).

- [ ] **Step 6: Improvement-log entry + commit**

```bash
git add src/temporal_exploit/hillclimb.py scripts/beat_epss_hillclimb.py tests/test_hillclimb_parallel.py docs/improvement_log_2026-07-02.md
git commit -m "perf(hillclimb): thread-parallel candidate evaluation (n_workers, default serial)"
```

---

### Task 7: Full verification, artifact refresh, docs sync

**Files:**
- Modify: `docs/improvement_log_2026-07-02.md` (final numbers), `docs/progress.md`, `README.md` (Project status / Scope for improvement)
- Refresh: `artifacts/` via build-dataset

- [ ] **Step 1: Bit-identity — fast build vs pre-change reference**

```bash
/usr/bin/time -v .venv/bin/python -m temporal_exploit.cli build-dataset \
  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \
  --artifact-dir <SCRATCH>/bench_after --snapshot-date 2026-03-14
.venv/bin/python - <<'EOF'
import pandas as pd, pathlib
ref, new = pathlib.Path("<SCRATCH>/bench_baseline"), pathlib.Path("<SCRATCH>/bench_after")
for p in sorted(ref.glob("*.parquet")):
    a, b = pd.read_parquet(p), pd.read_parquet(new / p.name)
    pd.testing.assert_frame_equal(a, b)
    print("identical:", p.name)
EOF
```

Expected: every parquet identical; wall-clock < 21.3 s baseline (record the number).

- [ ] **Step 2: Bit-identity — EPSS build vs pre-change reference** (same pattern against `<SCRATCH>/bench_epss`, adding `--epss-path epss_history-001.parquet`; expected identical, ~4 min, RSS ≤ 1.21 GB).

- [ ] **Step 3: Refresh the live artifacts** (current code + trajectory columns, enables the Task 3 cache for real):

```bash
/usr/bin/time -v .venv/bin/python -m temporal_exploit.cli build-dataset \
  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \
  --artifact-dir artifacts --epss-path epss_history-001.parquet --snapshot-date 2026-03-14
```

Then prove the cache pays: run `scripts/inwild_epss_ablation_landmark.py` and confirm from its stdout that no "building landmark EPSS trajectory ... 375M-row" scan happens and startup is seconds, not ~4 min.

- [ ] **Step 4: Suite + backtest timing final pass** — `.venv/bin/python -m pytest -q` green; re-run the Task 4 backtest timing once more post-all-changes; record final wall/RSS numbers.

- [ ] **Step 5: RE loops (standing rule)** — dispatch ≤2 review subagents, 3–5 loops each, over the bundle's diffs: hunt for behavior drift (esp. Task 1 regex vs dict parse on weird vectors, Task 4 filter/prepare commutation, Task 6 thread-safety of the injected evaluate). Fix anything found; re-run identity checks if code changed.

- [ ] **Step 6: Docs sync + final commit** — improvement log §Changes landed gets final before/after table; `docs/progress.md` + README status sections updated per repo convention.

```bash
git add docs/improvement_log_2026-07-02.md docs/progress.md README.md
git commit -m "docs: speed/memory bundle results — measured before/after + RE verdicts"
git push origin master
```

---

## Self-Review (done at write time)

- **Spec coverage:** S1→Task 3, S2→Task 4, S3→Tasks 1-2, S4→Tasks 5-6; measurement/RE/docs→Task 7. A1-A3/L1 are later plans by design.
- **Placeholders:** none; every code step is complete.
- **Type consistency:** `parse_cvss_vectors` consumed with `parsed[field]`/`== value` in both builders; `load_epss_at_landmark` returns corpus-ordered frame consumed by `.merge(on="cve_id", how="left")` in both scripts; `model_kwargs` dict flows `rolling_origin_backtest → _fit → fit_xgb_aft(**kw)`.
- **Known risk noted in-plan:** Task 4's filter/prepare commutation is asserted by the empty-diff gate in Step 5, not just argued; Task 1's last-occurrence regex is pinned by a duplicate-key test.
