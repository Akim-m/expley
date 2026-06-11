# Remediation and Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four review-confirmed critical defects in the existing modeling code, then complete the remaining phases (splits, artifacts, CLI, baselines, evaluation, docs, integration) of the temporal exploit modeling layer.

**Architecture:** Continues `docs/superpowers/plans/2026-06-10-temporal-exploit-modeling.md`. Tasks 1–22 of that plan are committed (through `7a3b10e`). A code review on 2026-06-12 found the label builder crashes on real tz-aware parquet data, `schema.py` and `features.py` encode wrong column names, and `list_len` returns 0 for numpy arrays — so this plan starts with a remediation phase, then supersedes the old plan's Tasks 23–44 with corrected, fully-specified versions. The handover data under `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/` stays immutable.

**Tech Stack:** Python 3.12+ (repo venv at `.venv/`), pandas, pyarrow, numpy, scikit-learn, lifelines, pytest.

**Run all commands from the repo root.** Use the venv interpreter: `./.venv/Scripts/python.exe -m pytest ...` (PowerShell: `.venv\Scripts\python.exe`).

---

## Ground truth: real parquet schemas

Verified 2026-06-12 against `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/`. All date columns are `timestamp[ns, tz=UTC]`; all list columns load as `numpy.ndarray`.

| Parquet | Key columns |
|---|---|
| `cve_corpus` | `cve_id`, `published`, `description`, `cwe_ids` (list), `cvss_v3_base` (double), `cvss_v3_severity`, `vendors` (list), `products` (list), `reference_count` |
| `poc_dates` | `cve_id`, `poc_first_seen` |
| `kev_events` | `cve_id`, `kev_date_added` |
| `metasploit_dates` | `cve_id`, `metasploit_first_seen` |
| `nuclei_dates` | `cve_id`, `nuclei_first_seen` |
| `google_0day` | `cve_id`, `zeroday_date_discovered` |

The committed code wrongly assumes `dateAdded`, `date_discovered`, `cvss_v3_base_score`, and `weaknesses`. Every remediation task below corrects toward this table.

---

## Standing rules (carried over from the 2026-06-10 plan)

- **Production novelty check before each commit:** does this improve reliability, reproducibility, interpretability, auditability, or operator experience? Small wins go in now; large ideas go to the backlog at the bottom.
- **Subtask sizing:** each task is one focused outcome, independently testable and committable.
- **TDD:** failing test first, minimal implementation, green, commit.

---

## Phase R: Remediation (must complete before anything else)

### Task R1: Make fixtures mirror real schemas

The tiny fixtures use naive string dates, Python lists, and wrong column names — which is exactly why the criticals slipped through. Fix the fixtures first so every later test exercises realistic data.

**Files:**
- Modify: `tests/fixtures/tiny_parquets.py`

- [ ] **Step 1: Rewrite the fixture with real column names and tz-aware dates**

```python
from pathlib import Path

import pandas as pd


def write_tiny_handover(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
            "cvss_v3_base": [9.8, 5.3],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM"],
            "cwe_ids": [["CWE-79"], ["CWE-89"]],
            "vendors": [["apache"], ["example"]],
            "products": [["httpd"], ["widget"]],
        }
    ).to_parquet(out_dir / "cve_corpus.parquet")
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": pd.to_datetime(["2024-01-10"], utc=True),
        }
    ).to_parquet(out_dir / "poc_dates.parquet")
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "kev_date_added": pd.to_datetime(["2024-01-20"], utc=True),
        }
    ).to_parquet(out_dir / "kev_events.parquet")
```

- [ ] **Step 2: Run the full suite to see what the schema correction breaks**

Run: `./.venv/Scripts/python.exe -m pytest -q`
Expected: failures in `tests/test_labels.py` (and possibly `tests/test_schema.py`) that reference `dateAdded` — these are fixed in R2/R3. Note the failures; do not fix them here.

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/tiny_parquets.py
git commit -m "test: align fixtures with real handover schemas"
```

### Task R2: Correct schema column names

**Files:**
- Modify: `src/temporal_exploit/schema.py`
- Modify: `tests/test_schema.py`

- [ ] **Step 1: Update the schema test to assert real column names**

Add to `tests/test_schema.py`:

```python
def test_required_columns_match_real_handover_names():
    assert REQUIRED_COLUMNS["kev_events"] == ("cve_id", "kev_date_added")
    assert REQUIRED_COLUMNS["google_0day"] == ("cve_id", "zeroday_date_discovered")
```

(Import `REQUIRED_COLUMNS` from `temporal_exploit.schema` at the top if not already imported.)

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_schema.py -v`
Expected: FAIL — current values are `dateAdded` and `date_discovered`.

- [ ] **Step 3: Fix `REQUIRED_COLUMNS` in `src/temporal_exploit/schema.py`**

```python
REQUIRED_COLUMNS: dict[str, tuple[str, ...]] = {
    "cve_corpus": ("cve_id", "published"),
    "poc_dates": ("cve_id", "poc_first_seen"),
    "kev_events": ("cve_id", "kev_date_added"),
    "metasploit_dates": ("cve_id", "metasploit_first_seen"),
    "nuclei_dates": ("cve_id", "nuclei_first_seen"),
    "google_0day": ("cve_id", "zeroday_date_discovered"),
}
```

- [ ] **Step 4: Update any `dateAdded` references in `tests/test_labels.py` to `kev_date_added`**

Search: `grep -rn "dateAdded" tests src` — replace every hit with `kev_date_added`.

- [ ] **Step 5: Run schema and label tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_schema.py tests/test_labels.py -v`
Expected: schema tests PASS; label tests may still fail on tz handling (fixed in R3).

- [ ] **Step 6: Commit**

```bash
git add src/temporal_exploit/schema.py tests/test_schema.py tests/test_labels.py
git commit -m "fix: correct kev and google 0day column names"
```

### Task R3: Fix timezone handling in labels

`build_first_weaponization_labels` crashes on real data: tz-aware `event_date` filled with a tz-naive snapshot becomes object dtype and the duration subtraction raises `TypeError`.

**Files:**
- Modify: `src/temporal_exploit/labels.py`
- Modify: `tests/test_labels.py`

- [ ] **Step 1: Write the failing tz-aware test**

Add to `tests/test_labels.py`:

```python
def test_labels_handle_tz_aware_dates():
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
        }
    )
    poc = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": pd.to_datetime(["2024-01-11"], utc=True),
        }
    )
    labels = build_first_weaponization_labels(
        corpus, {"poc": (poc, "poc_first_seen")}, snapshot_date="2024-03-01"
    )
    observed = labels.loc[labels["cve_id"] == "CVE-2024-0001"].iloc[0]
    censored = labels.loc[labels["cve_id"] == "CVE-2024-0002"].iloc[0]
    assert observed["duration_days"] == 10
    assert censored["event_source"] == "censored"
    assert censored["duration_days"] == 29
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_labels.py::test_labels_handle_tz_aware_dates -v`
Expected: FAIL with `TypeError` on the duration subtraction (or dtype mismatch).

- [ ] **Step 3: Normalize everything to UTC in `src/temporal_exploit/labels.py`**

Three changes:

In `first_event_per_cve` (line 9):
```python
    events["event_date"] = pd.to_datetime(events[date_col], errors="coerce", utc=True)
```

In `build_first_weaponization_labels` (line 23):
```python
    base["published"] = pd.to_datetime(base["published"], errors="coerce", utc=True)
```

And the snapshot (line 42):
```python
    snapshot = pd.Timestamp(snapshot_date, tz="UTC")
```

- [ ] **Step 4: Run all label tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_labels.py -v`
Expected: PASS (naive string-date tests still pass because `utc=True` localizes them).

- [ ] **Step 5: Commit**

```bash
git add src/temporal_exploit/labels.py tests/test_labels.py
git commit -m "fix: normalize label dates to utc"
```

### Task R4: Fix feature column names, ndarray handling, and silent fallbacks

Three defects in one module, fixed as one coherent change: real corpus columns are `cvss_v3_base` and `cwe_ids` (not `cvss_v3_base_score` / `weaknesses`); parquet list columns load as `numpy.ndarray` which `list_len` scores as 0; and `corpus.get(col, default)` silently degrades to all-zero features instead of erroring.

**Files:**
- Modify: `src/temporal_exploit/features.py`
- Modify: `tests/test_features.py`

- [ ] **Step 1: Write the failing tests**

Update `tests/test_features.py`. Replace references to `cvss_v3_base_score`/`weaknesses` with `cvss_v3_base`/`cwe_ids`, and add:

```python
import numpy as np
import pytest


def test_list_len_handles_numpy_arrays():
    assert list_len(np.array(["CWE-79", "CWE-89"])) == 2
    assert has_list_value(np.array(["CWE-79"])) == 1
    assert list_len(np.array([])) == 0


def test_features_require_real_corpus_columns():
    corpus = pd.DataFrame({"cve_id": ["CVE-2024-0001"], "published": ["2024-01-01"]})
    with pytest.raises(ValueError, match="cvss_v3_base"):
        build_publication_features(corpus)


def test_features_flag_missing_cvss():
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": ["2024-01-01", "2024-02-01"],
            "cvss_v3_base": [9.8, None],
            "cvss_v3_severity": ["CRITICAL", None],
            "cwe_ids": [["CWE-79"], []],
            "vendors": [["apache"], []],
            "products": [["httpd"], []],
        }
    )
    features = build_publication_features(corpus)
    assert features["cvss_v3_missing"].tolist() == [0, 1]
    assert features["cvss_v3_base"].tolist() == [9.8, 0.0]
```

- [ ] **Step 2: Run to verify they fail**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_features.py -v`
Expected: FAIL — numpy arrays score 0, missing columns don't raise, `cvss_v3_missing` doesn't exist.

- [ ] **Step 3: Rewrite `build_publication_features` and `list_len` in `src/temporal_exploit/features.py`**

```python
import numpy as np
import pandas as pd


def list_len(value: object) -> int:
    if isinstance(value, (list, tuple, np.ndarray)):
        return len(value)
    return 0


def has_list_value(value: object) -> int:
    return int(list_len(value) > 0)


def build_publication_features(corpus: pd.DataFrame) -> pd.DataFrame:
    required = ["cve_id", "published", "cvss_v3_base", "cvss_v3_severity", "cwe_ids", "vendors", "products"]
    missing = [column for column in required if column not in corpus.columns]
    if missing:
        raise ValueError(f"Missing required corpus columns: {missing}")

    features = corpus[["cve_id", "published"]].copy()
    features["published"] = pd.to_datetime(features["published"], errors="coerce", utc=True)
    features["published_year"] = features["published"].dt.year

    cvss = pd.to_numeric(corpus["cvss_v3_base"], errors="coerce")
    features["cvss_v3_missing"] = cvss.isna().astype(int)
    features["cvss_v3_base"] = cvss.fillna(0.0)

    severity = corpus["cvss_v3_severity"].fillna("UNKNOWN")
    severity_dummies = pd.get_dummies(severity, prefix="severity", dtype=int)
    features = pd.concat([features, severity_dummies], axis=1)

    features["has_weakness"] = corpus["cwe_ids"].map(has_list_value)
    features["weakness_count"] = corpus["cwe_ids"].map(list_len)
    features["vendor_count"] = corpus["vendors"].map(list_len)
    features["product_count"] = corpus["products"].map(list_len)
    return features
```

- [ ] **Step 4: Update `feature_provenance()` to match**

Change the `cvss_v3_base_score` entry's `feature_family`/`source` to `cvss_v3_base` / `cve_corpus.cvss_v3_base`, change the two `weaknesses` sources to `cve_corpus.cwe_ids`, and add:

```python
            {
                "feature_family": "cvss_v3_missing",
                "source": "cve_corpus.cvss_v3_base",
                "leakage_status": "publication_time_safe",
                "notes": "Missing-score indicator; 0.0 imputation alone would conflate missing with least-severe.",
            },
```

If a provenance test asserts feature names, update it to the new names and assert every column emitted by `build_publication_features` (except `cve_id`/`published`) has a provenance row.

- [ ] **Step 5: Run all feature tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_features.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/temporal_exploit/features.py tests/test_features.py
git commit -m "fix: use real corpus columns and handle ndarray lists"
```

### Task R5: Add end-to-end fixture-parquet regression test

One test that loads the fixture parquets from disk and runs the full labels + features path. This is the standing guard that would have caught every critical above.

**Files:**
- Create: `tests/test_end_to_end.py`

- [ ] **Step 1: Write the test**

```python
import pandas as pd

from temporal_exploit.features import build_publication_features
from temporal_exploit.labels import build_first_weaponization_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.schema import REQUIRED_COLUMNS, validate_columns
from tests.fixtures.tiny_parquets import write_tiny_handover


def test_labels_and_features_from_fixture_parquets(tmp_path):
    write_tiny_handover(tmp_path)
    corpus = load_parquet(tmp_path, "cve_corpus")
    poc = load_parquet(tmp_path, "poc_dates")
    kev = load_parquet(tmp_path, "kev_events")
    for name, frame in [("cve_corpus", corpus), ("poc_dates", poc), ("kev_events", kev)]:
        validate_columns(frame, name, REQUIRED_COLUMNS[name])

    labels = build_first_weaponization_labels(
        corpus,
        {"poc": (poc, "poc_first_seen"), "kev": (kev, "kev_date_added")},
        snapshot_date="2024-03-01",
    )
    observed = labels.loc[labels["cve_id"] == "CVE-2024-0001"].iloc[0]
    assert observed["event_source"] == "poc"
    assert observed["duration_days"] == 9
    censored = labels.loc[labels["cve_id"] == "CVE-2024-0002"].iloc[0]
    assert censored["event_source"] == "censored"

    features = build_publication_features(corpus)
    assert features["weakness_count"].tolist() == [1, 1]
    assert features["vendor_count"].tolist() == [1, 1]
```

- [ ] **Step 2: Run it**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_end_to_end.py -v`
Expected: PASS. If `weakness_count` comes back 0, the ndarray fix in R4 is wrong — stop and fix it.

- [ ] **Step 3: Run the full suite**

Run: `./.venv/Scripts/python.exe -m pytest -q`
Expected: all tests pass. (If `PermissionError` collection errors appear, rerun with `--basetemp` pointed at a writable dir — that is a sandbox artifact, not a code failure.)

- [ ] **Step 4: Commit**

```bash
git add tests/test_end_to_end.py
git commit -m "test: add fixture-parquet end-to-end regression"
```

---

## Phase 5: Time-based splits

### Task S1: Test time split

**Files:**
- Create: `tests/test_splits.py`

- [ ] **Step 1: Write the failing test**

```python
import pandas as pd

from temporal_exploit.splits import make_time_split


def _labels():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0003"],
            "published": pd.to_datetime(["2024-02-01", "2024-01-01", "2024-06-01"], utc=True),
            "event_observed": [True, False, False],
            "duration_days": [10, 60, 30],
        }
    )


def test_time_split_partitions_on_cutoff():
    split = make_time_split(_labels(), cutoff_date="2024-06-01")
    assert split.train["cve_id"].tolist() == ["CVE-2024-0001", "CVE-2024-0002"]
    assert split.test["cve_id"].tolist() == ["CVE-2024-0003"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_splits.py -v`
Expected: FAIL — `ModuleNotFoundError: temporal_exploit.splits`.

### Task S2: Implement time split

**Files:**
- Create: `src/temporal_exploit/splits.py`

- [ ] **Step 1: Implement**

```python
from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class TimeSplit:
    cutoff_date: pd.Timestamp
    train: pd.DataFrame
    test: pd.DataFrame


def make_time_split(labels: pd.DataFrame, cutoff_date: str) -> TimeSplit:
    cutoff = pd.Timestamp(cutoff_date, tz="UTC")
    ordered = labels.sort_values("cve_id").reset_index(drop=True)
    train = ordered[ordered["published"] < cutoff].reset_index(drop=True)
    test = ordered[ordered["published"] >= cutoff].reset_index(drop=True)
    return TimeSplit(cutoff_date=cutoff, train=train, test=test)
```

- [ ] **Step 2: Run tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_splits.py -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/temporal_exploit/splits.py tests/test_splits.py
git commit -m "feat: add time-based train test split"
```

### Task S3: Persist split files

**Files:**
- Modify: `src/temporal_exploit/splits.py`
- Modify: `tests/test_splits.py`

- [ ] **Step 1: Write the failing test**

```python
import json

from temporal_exploit.splits import make_time_split, write_time_split


def test_write_time_split_persists_ids_and_metadata(tmp_path):
    split = make_time_split(_labels(), cutoff_date="2024-06-01")
    write_time_split(split, tmp_path)
    train_ids = (tmp_path / "train_cve_ids.txt").read_text().splitlines()
    test_ids = (tmp_path / "test_cve_ids.txt").read_text().splitlines()
    metadata = json.loads((tmp_path / "split_metadata.json").read_text())
    assert train_ids == ["CVE-2024-0001", "CVE-2024-0002"]
    assert test_ids == ["CVE-2024-0003"]
    assert metadata == {"cutoff_date": "2024-06-01", "test_count": 1, "train_count": 2}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_splits.py -v`
Expected: FAIL — `write_time_split` not defined.

- [ ] **Step 3: Implement in `src/temporal_exploit/splits.py`**

```python
import json
from pathlib import Path


def write_time_split(split: TimeSplit, artifact_dir: Path) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "train_cve_ids.txt").write_text("\n".join(split.train["cve_id"]) + "\n")
    (artifact_dir / "test_cve_ids.txt").write_text("\n".join(split.test["cve_id"]) + "\n")
    metadata = {
        "cutoff_date": str(split.cutoff_date.date()),
        "train_count": len(split.train),
        "test_count": len(split.test),
    }
    (artifact_dir / "split_metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))
```

(Move the `import json` / `from pathlib import Path` lines to the top of the module with the other imports.)

- [ ] **Step 4: Run tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_splits.py -v` — expected PASS.

```bash
git add src/temporal_exploit/splits.py tests/test_splits.py
git commit -m "feat: persist time split artifacts"
```

---

## Phase 6: Artifact manifests

### Task A1: Test and implement manifest writer

**Files:**
- Create: `tests/test_artifacts.py`
- Create: `src/temporal_exploit/artifacts.py`

- [ ] **Step 1: Write the failing test**

```python
import json

from temporal_exploit.artifacts import write_manifest


def test_write_manifest_writes_sorted_json(tmp_path):
    path = tmp_path / "manifest.json"
    write_manifest(path, {"snapshot_date": "2026-03-14", "labels_rows": 2})
    loaded = json.loads(path.read_text())
    assert loaded["snapshot_date"] == "2026-03-14"
    assert loaded["labels_rows"] == 2
    assert "created_utc" in loaded
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_artifacts.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `src/temporal_exploit/artifacts.py`**

```python
import json
from datetime import datetime, timezone
from pathlib import Path


def write_manifest(path: Path, metadata: dict) -> None:
    payload = {**metadata, "created_utc": datetime.now(timezone.utc).isoformat()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
```

- [ ] **Step 4: Run tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_artifacts.py -v` — expected PASS.

```bash
git add src/temporal_exploit/artifacts.py tests/test_artifacts.py
git commit -m "feat: add artifact manifest writer"
```

---

## Phase 7: CLI dataset builder

### Task C1: Define event sources and optional loader

Column names below are the verified real names from the ground-truth table — do not "correct" them back.

**Files:**
- Create: `src/temporal_exploit/cli.py`

- [ ] **Step 1: Create the module**

```python
from pathlib import Path

import pandas as pd

from temporal_exploit.loaders import load_parquet
from temporal_exploit.schema import validate_columns

EVENT_SOURCES: dict[str, tuple[str, str]] = {
    "poc": ("poc_dates", "poc_first_seen"),
    "metasploit": ("metasploit_dates", "metasploit_first_seen"),
    "nuclei": ("nuclei_dates", "nuclei_first_seen"),
    "kev": ("kev_events", "kev_date_added"),
    "google_0day": ("google_0day", "zeroday_date_discovered"),
}


def load_optional_event(out_dir: Path, parquet_name: str, date_col: str) -> pd.DataFrame | None:
    try:
        frame = load_parquet(out_dir, parquet_name)
    except FileNotFoundError:
        return None
    validate_columns(frame, parquet_name, ("cve_id", date_col))
    return frame
```

- [ ] **Step 2: Commit**

```bash
git add src/temporal_exploit/cli.py
git commit -m "feat: define modeling event sources"
```

### Task C2: Test dataset builder command

**Files:**
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
import json

import pandas as pd

from temporal_exploit.cli import build_dataset_command
from tests.fixtures.tiny_parquets import write_tiny_handover


def test_build_dataset_writes_artifacts(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)

    build_dataset_command(out_dir, artifact_dir, snapshot_date="2024-03-01")

    labels = pd.read_parquet(artifact_dir / "modeling_labels.parquet")
    features = pd.read_parquet(artifact_dir / "publication_features.parquet")
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert set(labels["cve_id"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert "cvss_v3_base" in features.columns
    assert manifest["snapshot_date"] == "2024-03-01"
    assert manifest["event_source_rows"]["poc"] == 1
    assert manifest["event_source_rows"]["kev"] == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_cli.py -v`
Expected: FAIL — `build_dataset_command` not defined.

### Task C3: Implement dataset builder command

**Files:**
- Modify: `src/temporal_exploit/cli.py`

- [ ] **Step 1: Implement**

Add to `src/temporal_exploit/cli.py`:

```python
from temporal_exploit.artifacts import write_manifest
from temporal_exploit.features import build_publication_features
from temporal_exploit.labels import build_first_weaponization_labels
from temporal_exploit.schema import REQUIRED_COLUMNS


def build_dataset_command(out_dir: Path, artifact_dir: Path, snapshot_date: str) -> None:
    corpus = load_parquet(out_dir, "cve_corpus")
    validate_columns(corpus, "cve_corpus", REQUIRED_COLUMNS["cve_corpus"])

    event_frames: dict[str, tuple[pd.DataFrame, str]] = {}
    event_source_rows: dict[str, int] = {}
    for source, (parquet_name, date_col) in EVENT_SOURCES.items():
        frame = load_optional_event(out_dir, parquet_name, date_col)
        if frame is not None:
            event_frames[source] = (frame, date_col)
            event_source_rows[source] = len(frame)

    labels = build_first_weaponization_labels(corpus, event_frames, snapshot_date)
    features = build_publication_features(corpus)

    artifact_dir.mkdir(parents=True, exist_ok=True)
    labels.to_parquet(artifact_dir / "modeling_labels.parquet", index=False)
    features.to_parquet(artifact_dir / "publication_features.parquet", index=False)
    write_manifest(
        artifact_dir / "manifest.json",
        {
            "snapshot_date": snapshot_date,
            "corpus_rows": len(corpus),
            "labels_rows": len(labels),
            "features_rows": len(features),
            "event_source_rows": event_source_rows,
        },
    )
```

Note: `build_publication_features` requires the full corpus feature columns (R4). The fixture corpus has them; the real corpus has them. If a stripped corpus is ever used, the explicit `ValueError` is the desired behavior.

- [ ] **Step 2: Run tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_cli.py -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/temporal_exploit/cli.py tests/test_cli.py
git commit -m "feat: build modeling dataset artifacts"
```

### Task C4: Add command-line parser

**Files:**
- Modify: `src/temporal_exploit/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
from temporal_exploit.cli import main


def test_main_build_dataset_smoke(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)
    main(
        [
            "build-dataset",
            "--out-dir", str(out_dir),
            "--artifact-dir", str(artifact_dir),
            "--snapshot-date", "2024-03-01",
        ]
    )
    assert (artifact_dir / "manifest.json").exists()
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_cli.py::test_main_build_dataset_smoke -v`
Expected: FAIL — `main` not defined.

- [ ] **Step 3: Implement `main` in `src/temporal_exploit/cli.py`**

```python
import argparse


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="temporal-exploit")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-dataset", help="Build modeling labels and features")
    build.add_argument("--out-dir", type=Path, required=True)
    build.add_argument("--artifact-dir", type=Path, required=True)
    build.add_argument("--snapshot-date", required=True)
    args = parser.parse_args(argv)
    if args.command == "build-dataset":
        build_dataset_command(args.out_dir, args.artifact_dir, args.snapshot_date)
```

- [ ] **Step 4: Run all CLI tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_cli.py -v` — expected PASS.

```bash
git add src/temporal_exploit/cli.py tests/test_cli.py
git commit -m "feat: add modeling cli entry point"
```

---

## Phase 8: Baselines

Requires `lifelines` (already in pyproject dependencies). If imports fail, run `./.venv/Scripts/python.exe -m pip install -e ".[dev]"` first.

### Task B1: Kaplan-Meier baseline

**Files:**
- Create: `tests/test_baselines.py`
- Create: `src/temporal_exploit/baselines.py`

- [ ] **Step 1: Write the failing test**

```python
import pandas as pd

from temporal_exploit.baselines import fit_kaplan_meier


def _labels():
    return pd.DataFrame(
        {
            "duration_days": [5, 10, 30, 60, 90],
            "event_observed": [True, True, False, True, False],
        }
    )


def test_kaplan_meier_returns_survival_function():
    fitter = fit_kaplan_meier(_labels())
    assert not fitter.survival_function_.empty
    assert fitter.survival_function_.columns.tolist() == ["first_weaponization"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_baselines.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `src/temporal_exploit/baselines.py`**

```python
import pandas as pd
from lifelines import KaplanMeierFitter


def fit_kaplan_meier(labels: pd.DataFrame) -> KaplanMeierFitter:
    fitter = KaplanMeierFitter(label="first_weaponization")
    fitter.fit(labels["duration_days"], event_observed=labels["event_observed"])
    return fitter
```

Callers must filter `negative_duration_flag` rows before fitting — lifelines rejects negative durations with its own clear error, and silently dropping rows inside the fit helper would hide data problems.

- [ ] **Step 4: Run tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_baselines.py -v` — expected PASS.

```bash
git add src/temporal_exploit/baselines.py tests/test_baselines.py
git commit -m "feat: add kaplan meier baseline"
```

### Task B2: Cox baseline

**Files:**
- Modify: `tests/test_baselines.py`
- Modify: `src/temporal_exploit/baselines.py`

- [ ] **Step 1: Write the failing test**

```python
from temporal_exploit.baselines import fit_cox_baseline


def test_cox_baseline_fits_numeric_feature():
    frame = pd.DataFrame(
        {
            "duration_days": [5, 10, 30, 60, 90, 120, 15, 45],
            "event_observed": [True, True, False, True, False, False, True, True],
            "cvss_v3_base": [9.8, 7.5, 5.3, 8.8, 4.3, 3.1, 9.1, 6.5],
        }
    )
    fitter = fit_cox_baseline(frame, ["cvss_v3_base"])
    assert "cvss_v3_base" in fitter.params_.index
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_baselines.py::test_cox_baseline_fits_numeric_feature -v`
Expected: FAIL — `fit_cox_baseline` not defined.

- [ ] **Step 3: Implement**

Add to `src/temporal_exploit/baselines.py`:

```python
from lifelines import CoxPHFitter


def fit_cox_baseline(frame: pd.DataFrame, feature_cols: list[str]) -> CoxPHFitter:
    columns = ["duration_days", "event_observed", *feature_cols]
    fitter = CoxPHFitter()
    fitter.fit(frame[columns], duration_col="duration_days", event_col="event_observed")
    return fitter
```

- [ ] **Step 4: Run tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_baselines.py -v` — expected PASS.

```bash
git add src/temporal_exploit/baselines.py tests/test_baselines.py
git commit -m "feat: add cox baseline"
```

Proportional-hazards diagnostics (`fitter.check_assumptions`) are a required follow-up before interpreting coefficients — record this in the methodology doc (Task D1).

---

## Phase 9: Evaluation

### Task E1: Event rate by horizon

**Files:**
- Create: `tests/test_evaluate.py`
- Create: `src/temporal_exploit/evaluate.py`

- [ ] **Step 1: Write the failing test**

```python
import pandas as pd

from temporal_exploit.evaluate import event_rate_by_horizon


def _labels():
    return pd.DataFrame(
        {
            "cve_id": ["a", "b", "c", "d"],
            "event_observed": [True, True, False, False],
            "duration_days": [5, 45, 100, 200],
            "event_source": ["poc", "kev", "censored", "censored"],
        }
    )


def test_event_rate_by_horizon():
    rates = event_rate_by_horizon(_labels(), horizons=[7, 30, 90, 180])
    assert rates["horizon_days"].tolist() == [7, 30, 90, 180]
    assert rates["observed_events"].tolist() == [1, 1, 2, 2]
    assert rates["n"].tolist() == [4, 4, 4, 4]
    assert rates["observed_event_rate"].tolist() == [0.25, 0.25, 0.5, 0.5]
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_evaluate.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `src/temporal_exploit/evaluate.py`**

```python
import pandas as pd


def event_rate_by_horizon(labels: pd.DataFrame, horizons: list[int]) -> pd.DataFrame:
    n = len(labels)
    rows = []
    for horizon in horizons:
        observed = int((labels["event_observed"] & (labels["duration_days"] <= horizon)).sum())
        rows.append(
            {
                "horizon_days": horizon,
                "observed_events": observed,
                "n": n,
                "observed_event_rate": observed / n if n else 0.0,
            }
        )
    return pd.DataFrame(rows)
```

- [ ] **Step 4: Run tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_evaluate.py -v` — expected PASS.

```bash
git add src/temporal_exploit/evaluate.py tests/test_evaluate.py
git commit -m "feat: summarize event rates by horizon"
```

### Task E2: Event-source composition summary

**Files:**
- Modify: `tests/test_evaluate.py`
- Modify: `src/temporal_exploit/evaluate.py`

- [ ] **Step 1: Write the failing test**

```python
from temporal_exploit.evaluate import event_source_counts


def test_event_source_counts():
    counts = event_source_counts(_labels())
    by_source = counts.set_index("event_source")
    assert by_source.loc["censored", "count"] == 2
    assert by_source.loc["censored", "pct"] == 50.0
    assert by_source.loc["poc", "count"] == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_evaluate.py::test_event_source_counts -v`
Expected: FAIL — `event_source_counts` not defined.

- [ ] **Step 3: Implement**

Add to `src/temporal_exploit/evaluate.py`:

```python
def event_source_counts(labels: pd.DataFrame) -> pd.DataFrame:
    counts = labels["event_source"].value_counts(dropna=False)
    return pd.DataFrame(
        {
            "event_source": counts.index,
            "count": counts.to_numpy(),
            "pct": (counts / counts.sum() * 100).round(2).to_numpy(),
        }
    )
```

- [ ] **Step 4: Run tests, then commit**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_evaluate.py -v` — expected PASS.

```bash
git add src/temporal_exploit/evaluate.py tests/test_evaluate.py
git commit -m "feat: summarize event source composition"
```

---

## Phase 10: Documentation

### Task D1: Modeling methodology

**Files:**
- Create: `docs/modeling_methodology.md`

- [ ] **Step 1: Write the methodology document** covering, in order:

1. **Target:** time from CVE publication to first public weaponization signal (earliest of PoC, Metasploit, Nuclei, KEV, Google 0-day discovery).
2. **Clock origin:** `cve_corpus.published` (UTC). All event dates normalized to UTC.
3. **Censoring:** CVEs without an observed event are right-censored at the snapshot date (`event_source == "censored"`). Note censoring is potentially informative (older CVEs have longer exposure).
4. **Negative durations:** events dated before publication are flagged (`negative_duration_flag`) and preserved, not dropped — they expose pre-disclosure or backdated signals. Baselines must exclude them before fitting.
5. **Leakage controls:** features restricted to publication-time structured metadata (`cvss_v3_base` + missing indicator, severity one-hot, `cwe_ids`/vendor/product counts, publication year). No description text, no snapshot-time presence flags, no snapshot EPSS. Reference `feature_provenance()` as the audit trail.
6. **Splits:** time-based on `published` at a fixed cutoff; locked ID files written to artifacts. No random K-fold.
7. **Baselines:** Kaplan-Meier reference curve; Cox PH on numeric features. State that PH-assumption diagnostics are required before interpreting coefficients.
8. **Evaluation horizons:** 7 / 30 / 90 / 180 days; naive event-rate-by-horizon as the floor any model must beat.
9. **Known biases:** PoC source dominance, public-signal framing (not in-the-wild exploitation), NVD metadata revisions over time.
10. **Production-novelty contributions:** schema validation, artifact manifests, feature provenance, locked splits, negative-duration flags.

- [ ] **Step 2: Commit**

```bash
git add docs/modeling_methodology.md
git commit -m "docs: add modeling methodology"
```

### Task D2: README quick start

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "Modeling quick start" section** after the existing dataset quick start:

````markdown
## Modeling quick start

From the repo root:

```bash
python -m pip install -e ".[dev]"
temporal-exploit build-dataset --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out --artifact-dir artifacts --snapshot-date 2026-03-14
pytest
```

Generated artifacts land in `artifacts/` (ignored by Git): `modeling_labels.parquet`,
`publication_features.parquet`, and `manifest.json`. Methodology is documented in
`docs/modeling_methodology.md`.
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add modeling quick start"
```

---

## Phase 11: Integration checkpoints

### Task I1: Full test suite

- [ ] Run: `./.venv/Scripts/python.exe -m pytest -v`
- [ ] Expected: all tests pass. Keep any fixes minimal and commit them as `fix: stabilize modeling tests`.

### Task I2: Build real artifacts

- [ ] Run:

```bash
./.venv/Scripts/python.exe -m temporal_exploit.cli build-dataset --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out --artifact-dir artifacts --snapshot-date 2026-03-14
```

(If the module-style invocation fails because `cli.py` has no `__main__` guard, use the console script `temporal-exploit` after `pip install -e .`, or add `if __name__ == "__main__": main()` to `cli.py`.)

- [ ] Expected files: `artifacts/modeling_labels.parquet`, `artifacts/publication_features.parquet`, `artifacts/manifest.json`.
- [ ] **Validation gate (this is the real-data proof the review demanded):**

```bash
./.venv/Scripts/python.exe -c "
import pandas as pd
df = pd.read_parquet('artifacts/modeling_labels.parquet')
feats = pd.read_parquet('artifacts/publication_features.parquet')
print(df['event_source'].value_counts(dropna=False))
print(df[['event_observed','duration_days','negative_duration_flag']].describe())
print(feats[['cvss_v3_base','weakness_count','vendor_count','product_count']].describe())
"
```

Expected sanity checks — stop and investigate if any fail:
- `event_source` includes `poc`, `kev`, `censored` with nonzero counts (PoC likely dominant).
- `cvss_v3_base` is NOT all 0.0 (mean should be roughly 6–8).
- `weakness_count` / `vendor_count` / `product_count` are NOT all 0 — if they are, the ndarray fix regressed.

### Task I3: Record label composition

- [ ] Add a short "Observed label composition (snapshot 2026-03-14)" note to `docs/modeling_methodology.md` with the event-source counts and negative-duration count from I2.
- [ ] Commit: `git add docs/modeling_methodology.md && git commit -m "docs: record initial label composition notes"`

### Task I4: Final review and wrap-up

- [ ] Dispatch a code-review subagent over the range `7a3b10e..HEAD` (per superpowers:requesting-code-review). Fix Critical/Important findings before finishing.
- [ ] Confirm clean status: `git status --short` (the two untracked `.docx` files at repo root are user documents — leave them).
- [ ] Use superpowers:finishing-a-development-branch to decide merge/PR/push.

---

## Future production/novelty backlog (unchanged from 2026-06-10 plan)

- Schema report command printing all parquet columns and row counts.
- Artifact hashes in `manifest.json`.
- Feature provenance export as `artifacts/feature_provenance.csv`.
- Event-source dominance warnings.
- Cox PH diagnostics; calibration plots at 7/30/90/180 days.
- ATT&CK tactic aggregation from `technique_cwe_chain.parquet`.
- EPSS-at-publication features (separated from EPSS-at-snapshot).
- Model-card documentation for released models.

---

## Self-review

- **Spec coverage:** Review criticals 1–4 → Tasks R2–R4; Important 5 (CVSS missing indicator) → R4; Important 6–7 (fixture realism + end-to-end test) → R1/R5. Old-plan Tasks 23–44 → Phases 5–11 here (splits S1–S3, manifests A1, CLI C1–C4, baselines B1–B2, evaluation E1–E2, docs D1–D2, integration I1–I4). The old plan's flagged risk (unverified `EVENT_SOURCES` column names) is resolved with verified names in C1.
- **Placeholder scan:** every code step contains the actual code; D1 lists concrete content per section rather than "document the methodology".
- **Type consistency:** `build_first_weaponization_labels(corpus, event_frames: dict[str, tuple[DataFrame, str]], snapshot_date)` is used identically in R3, R5, and C3; feature column is `cvss_v3_base` everywhere after R4 (tests in B2 and the I2 gate use the same name); `TimeSplit.cutoff_date` is a `pd.Timestamp` and `write_time_split` formats it via `.date()`.
