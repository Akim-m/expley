# Interval-Censored PoC Modelling — Implementation Plan (Bucket A / §3.2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Model time-to-PoC with interval-censoring at bin resolution so GitHub indexing-batch dates stop masquerading as exact event times, and quantify the bias the exact-date treatment introduced.

**Architecture:** One new leakage-safe module `interval_censored.py` with three pure pieces — (1) person-period expansion, (2) a discrete-time logistic hazard model exposing the project's standard `feature_cols_`/`risk_scores`/`survival_at` interface, (3) a grouped-interval NPMLE (actuarial life-table) vs naive-KM bias exhibit — plus a runner script that fits on real `per_signal_labels` and writes metrics + a figure. TDD throughout, tiny fixtures, CPU-only.

**Tech Stack:** Python 3.12, numpy/pandas, `sklearn.linear_model.LogisticRegression` (hazard fit), `lifelines.KaplanMeierFitter` (naive baseline), matplotlib (figure). All already installed in `.venv`.

## Global Constraints

- Memory: **≤6–8 GB system RAM, ≤7 GB VRAM** for every step (this bucket is CPU-only tabular — trivially within budget; no GPU used).
- Env: `uv`-managed `.venv`; run tests with `.venv/bin/python -m pytest -q` (FutureWarning-as-error gate is baked into `pyproject.toml`).
- Leakage firewall: features come only from `build_publication_features` output (publication-time-knowable). No `description`, no snapshot EPSS/presence flags.
- Timezone: all date columns are `timestamp[ns, tz=UTC]`; normalize with `utc=True`.
- List columns load as `numpy.ndarray`, not lists.
- Push after each commit (`git push origin master`).
- Canonical bins (module constant): `HORIZON_BINS = (0.0, 7.0, 30.0, 90.0, 180.0, 365.0, 730.0, inf)` — the project's `(7,30,90,180)` eval horizons are edges `e₁…e₄`.

---

### Task A1: Person-period expansion

**Files:**
- Create: `src/temporal_exploit/interval_censored.py`
- Test: `tests/test_interval_censored.py`

**Interfaces:**
- Produces: `HORIZON_BINS: tuple[float, ...]`; `bin_index(duration: float, bin_edges) -> int` (index `k` of bin `(e_k, e_{k+1}]` containing `duration`); `expand_person_period(durations: np.ndarray, events: np.ndarray, features: pd.DataFrame, bin_edges=HORIZON_BINS) -> pd.DataFrame` returning long frame with columns `[*features.columns, "bin_idx", "y"]`, one row per (subject, bin) for bins `0..k_i` where `k_i = bin_index(duration_i)`; `y=1` only in bin `k_i` when `events_i` is truthy.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_interval_censored.py
import numpy as np
import pandas as pd
import pytest

from temporal_exploit import interval_censored as ic


def test_bin_index_places_duration_in_half_open_bin():
    edges = (0.0, 7.0, 30.0, 90.0, float("inf"))
    assert ic.bin_index(45.0, edges) == 2      # 30 < 45 <= 90 -> bin 2
    assert ic.bin_index(7.0, edges) == 0       # 0 < 7 <= 7   -> bin 0 (right-closed)
    assert ic.bin_index(7.5, edges) == 1       # 7 < 7.5 <= 30 -> bin 1
    assert ic.bin_index(200.0, edges) == 3     # 90 < 200      -> bin 3 (inf)


def test_expand_person_period_event_and_censored():
    edges = (0.0, 7.0, 30.0, 90.0, float("inf"))
    durations = np.array([45.0, 200.0])       # subject 0 event in bin 2, subject 1 censored bin 3
    events = np.array([1, 0])
    features = pd.DataFrame({"cvss": [9.8, 5.0]})
    long = ic.expand_person_period(durations, events, features, edges)
    s0 = long[long["cvss"] == 9.8].sort_values("bin_idx")
    assert list(s0["bin_idx"]) == [0, 1, 2]
    assert list(s0["y"]) == [0, 0, 1]         # event only in its containing bin
    s1 = long[long["cvss"] == 5.0].sort_values("bin_idx")
    assert list(s1["bin_idx"]) == [0, 1, 2, 3]
    assert list(s1["y"]) == [0, 0, 0, 0]      # censored -> never fires
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py -q`
Expected: FAIL — `AttributeError: module 'temporal_exploit.interval_censored' has no attribute 'bin_index'` (module does not exist yet).

- [ ] **Step 3: Write minimal implementation**

```python
# src/temporal_exploit/interval_censored.py
"""Interval-censored (bin-resolution) time-to-PoC modelling.

PoC 'event dates' are contaminated by repository-indexing batches (half of all
PoC records fall on 36 of 2,191 dates), so the recorded date is an upper bound,
not the true appearance time. Binning the timeline and treating the event as
occurring *in its containing bin* is grouped interval-censoring: within-bin
batch-date exactness is destroyed while coarse timing is preserved.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

HORIZON_BINS: tuple[float, ...] = (0.0, 7.0, 30.0, 90.0, 180.0, 365.0, 730.0, float("inf"))


def bin_index(duration: float, bin_edges: tuple[float, ...] = HORIZON_BINS) -> int:
    """Index k of the half-open bin (e_k, e_{k+1}] containing `duration` (> 0)."""
    for k in range(len(bin_edges) - 1):
        if bin_edges[k] < duration <= bin_edges[k + 1]:
            return k
    raise ValueError(f"duration {duration} outside {bin_edges}")


def expand_person_period(
    durations: np.ndarray,
    events: np.ndarray,
    features: pd.DataFrame,
    bin_edges: tuple[float, ...] = HORIZON_BINS,
) -> pd.DataFrame:
    """Long (person-period) frame: one row per (subject, bin) up to the subject's
    containing bin; `y=1` only in that bin when the subject had an event."""
    durations = np.asarray(durations, dtype=float)
    events = np.asarray(events).astype(int)
    if np.any(durations <= 0):
        raise ValueError("durations must be > 0 (filter negative/zero upstream)")
    feats = features.reset_index(drop=True)
    rows = []
    for i in range(len(durations)):
        k_i = bin_index(durations[i], bin_edges)
        for k in range(k_i + 1):
            row = feats.iloc[i].to_dict()
            row["bin_idx"] = k
            row["y"] = int(events[i] == 1 and k == k_i)
            rows.append(row)
    return pd.DataFrame(rows)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add src/temporal_exploit/interval_censored.py tests/test_interval_censored.py
git commit -m "feat(interval-censored): person-period expansion for time-to-PoC (§3.2 A1)"
git push origin master
```

---

### Task A2: Discrete-time logistic hazard model

**Files:**
- Modify: `src/temporal_exploit/interval_censored.py`
- Test: `tests/test_interval_censored.py`

**Interfaces:**
- Consumes: `expand_person_period`, `HORIZON_BINS`, `bin_index` from A1.
- Produces: `class DiscreteTimeModel` with attributes `feature_cols_: list[str]`, `bin_edges_: tuple[float, ...]`; methods `survival_at(X: pd.DataFrame, horizons) -> np.ndarray` (shape `(n, len(horizons))`, each `S(τ|x)=Π_{k: e_{k+1}<=τ}(1-h_k(x))`), `risk_scores(X: pd.DataFrame) -> np.ndarray` (`1 - S(last finite edge)`, monotone ranking score in `[0,1]`). Factory `fit_discrete_time(durations, events, features, bin_edges=HORIZON_BINS) -> DiscreteTimeModel` fits `sklearn.LogisticRegression(fit_intercept=False)` on `[features, one-hot(bin_idx)]` so each bin gets its own baseline hazard `γ_k`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_interval_censored.py
def test_discrete_time_recovers_hazard_and_is_monotone():
    # Two bins, feature-free: bin 0 hazard ~0.1, bin 1 hazard ~0.5 by construction.
    edges = (0.0, 10.0, 20.0, float("inf"))
    rng = np.random.default_rng(0)
    n = 4000
    # everyone at risk through bin 0; 10% event in bin0, of survivors 50% in bin1
    dur, ev = [], []
    for _ in range(n):
        if rng.random() < 0.1:
            dur.append(5.0); ev.append(1)                 # event bin 0
        elif rng.random() < 0.5:
            dur.append(15.0); ev.append(1)                # event bin 1
        else:
            dur.append(25.0); ev.append(0)                # censored bin 2
    features = pd.DataFrame({"x": np.zeros(n)})
    m = ic.fit_discrete_time(np.array(dur), np.array(ev), features, edges)
    S = m.survival_at(pd.DataFrame({"x": [0.0]}), horizons=(10.0, 20.0))[0]
    assert 0.0 <= S[1] <= S[0] <= 1.0                     # monotone non-increasing
    assert abs(S[0] - 0.9) < 0.05                          # S(10) ~ 1-0.1
    r = m.risk_scores(pd.DataFrame({"x": [0.0]}))
    assert 0.0 <= r[0] <= 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py::test_discrete_time_recovers_hazard_and_is_monotone -q`
Expected: FAIL — `AttributeError: module 'temporal_exploit.interval_censored' has no attribute 'fit_discrete_time'`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to src/temporal_exploit/interval_censored.py
from sklearn.linear_model import LogisticRegression


class DiscreteTimeModel:
    def __init__(self, clf: LogisticRegression, feature_cols: list[str], bin_edges: tuple[float, ...]):
        self._clf = clf
        self.feature_cols_ = feature_cols
        self.bin_edges_ = bin_edges
        self._n_bins = len(bin_edges) - 1

    def _design(self, X: pd.DataFrame, bin_idx: int) -> np.ndarray:
        feat = X[self.feature_cols_].to_numpy(dtype=float)
        onehot = np.zeros((len(X), self._n_bins), dtype=float)
        onehot[:, bin_idx] = 1.0
        return np.hstack([feat, onehot])

    def _hazard(self, X: pd.DataFrame, bin_idx: int) -> np.ndarray:
        return self._clf.predict_proba(self._design(X, bin_idx))[:, 1]

    def survival_at(self, X: pd.DataFrame, horizons) -> np.ndarray:
        out = np.ones((len(X), len(horizons)), dtype=float)
        for j, tau in enumerate(horizons):
            surv = np.ones(len(X), dtype=float)
            for k in range(self._n_bins):
                if self.bin_edges_[k + 1] <= tau:          # bin fully completed by tau
                    surv *= 1.0 - self._hazard(X, k)
            out[:, j] = surv
        return out

    def risk_scores(self, X: pd.DataFrame) -> np.ndarray:
        last_finite = self.bin_edges_[-2]                  # largest finite edge (730)
        return 1.0 - self.survival_at(X, (last_finite,))[:, 0]


def fit_discrete_time(durations, events, features, bin_edges=HORIZON_BINS) -> DiscreteTimeModel:
    feature_cols = list(features.columns)
    long = expand_person_period(durations, events, features, bin_edges)
    n_bins = len(bin_edges) - 1
    onehot = np.zeros((len(long), n_bins), dtype=float)
    onehot[np.arange(len(long)), long["bin_idx"].to_numpy(int)] = 1.0
    design = np.hstack([long[feature_cols].to_numpy(dtype=float), onehot])
    clf = LogisticRegression(fit_intercept=False, max_iter=1000, C=1e6)
    clf.fit(design, long["y"].to_numpy(int))
    return DiscreteTimeModel(clf, feature_cols, bin_edges)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/temporal_exploit/interval_censored.py tests/test_interval_censored.py
git commit -m "feat(interval-censored): discrete-time logistic hazard model (§3.2 A2)"
git push origin master
```

---

### Task A3: Grouped-NPMLE (life-table) vs naive-KM bias exhibit

**Files:**
- Modify: `src/temporal_exploit/interval_censored.py`
- Test: `tests/test_interval_censored.py`

**Interfaces:**
- Consumes: `HORIZON_BINS` from A1.
- Produces: `naive_km_survival(durations, events, grid) -> np.ndarray` (KM survival evaluated at each grid point via `lifelines.KaplanMeierFitter`); `grouped_life_table(durations, events, bin_edges=HORIZON_BINS) -> np.ndarray` (actuarial survival at each finite bin edge `e₁…e_{K-1}`, i.e. the grouped interval-censored NPMLE); `bias_divergence(durations, events, bin_edges=HORIZON_BINS) -> dict` with keys `max_abs_diff`, `mean_abs_diff`, `median_time_naive`, `median_time_lifetable` (median = first edge where survival ≤ 0.5, or `inf`).

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_interval_censored.py
def test_grouped_life_table_hand_computed():
    # edges (0,10,20,inf): bin0 has 2 events of 5 at risk; bin1 has 1 event of 3 at risk.
    edges = (0.0, 10.0, 20.0, float("inf"))
    dur = np.array([5.0, 5.0, 15.0, 25.0, 25.0])     # 2 events bin0, 1 event bin1, 2 censored bin2
    ev = np.array([1, 1, 1, 0, 0])
    surv = ic.grouped_life_table(dur, ev, edges)     # at edges 10 and 20
    # S(10) = 1 - 2/5 = 0.6 ; S(20) = 0.6 * (1 - 1/3) = 0.4
    assert np.allclose(surv, [0.6, 0.4], atol=1e-9)


def test_bias_divergence_flags_batching():
    edges = (0.0, 10.0, 20.0, float("inf"))
    dur = np.array([5.0, 5.0, 15.0, 25.0, 25.0])
    ev = np.array([1, 1, 1, 0, 0])
    out = ic.bias_divergence(dur, ev, edges)
    assert set(out) >= {"max_abs_diff", "mean_abs_diff", "median_time_naive", "median_time_lifetable"}
    assert out["max_abs_diff"] >= 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py::test_grouped_life_table_hand_computed -q`
Expected: FAIL — `AttributeError: ... has no attribute 'grouped_life_table'`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to src/temporal_exploit/interval_censored.py
from lifelines import KaplanMeierFitter


def naive_km_survival(durations, events, grid) -> np.ndarray:
    kmf = KaplanMeierFitter()
    kmf.fit(np.asarray(durations, float), np.asarray(events).astype(int))
    return kmf.survival_function_at_times(list(grid)).to_numpy()


def grouped_life_table(durations, events, bin_edges=HORIZON_BINS) -> np.ndarray:
    """Actuarial survival at each finite bin edge e_1..e_{K-1} (grouped interval NPMLE)."""
    durations = np.asarray(durations, float)
    events = np.asarray(events).astype(int)
    n_bins = len(bin_edges) - 1
    surv, running, at_risk = [], 1.0, len(durations)
    for k in range(n_bins):
        lo, hi = bin_edges[k], bin_edges[k + 1]
        in_bin = (durations > lo) & (durations <= hi)
        d_k = int(np.sum(in_bin & (events == 1)))
        w_k = int(np.sum(in_bin & (events == 0)))          # censored in bin
        effective = at_risk - w_k / 2.0
        running *= 1.0 - (d_k / effective if effective > 0 else 0.0)
        at_risk -= (d_k + w_k)
        if np.isfinite(hi):
            surv.append(running)
    return np.array(surv)


def _median_time(edges: tuple[float, ...], survival: np.ndarray) -> float:
    for e, s in zip(edges[1:], survival):
        if s <= 0.5:
            return float(e)
    return float("inf")


def bias_divergence(durations, events, bin_edges=HORIZON_BINS) -> dict:
    finite_edges = [e for e in bin_edges[1:] if np.isfinite(e)]
    lifetable = grouped_life_table(durations, events, bin_edges)
    naive = naive_km_survival(durations, events, finite_edges)
    diff = np.abs(naive - lifetable)
    return {
        "max_abs_diff": float(np.max(diff)),
        "mean_abs_diff": float(np.mean(diff)),
        "median_time_naive": _median_time(bin_edges, naive),
        "median_time_lifetable": _median_time(bin_edges, lifetable),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/temporal_exploit/interval_censored.py tests/test_interval_censored.py
git commit -m "feat(interval-censored): grouped-NPMLE vs naive-KM bias exhibit (§3.2 A3)"
git push origin master
```

---

### Task A4: Real-data runner, metrics + figure, RE loop

**Files:**
- Create: `scripts/build_interval_censored.py`
- Test: `tests/test_interval_censored.py` (smoke)

**Interfaces:**
- Consumes: `fit_discrete_time`, `survival_at`, `risk_scores`, `bias_divergence` (A1–A3); `per_signal_labels.parquet` (`poc_duration_days`, `poc_observed`, `poc_negative_duration_flag`) + `publication_features.parquet`; `splits.make_time_split` for the 2024-01-01 cutoff; `lifelines.utils.concordance_index` for the head-to-head.
- Produces: `run_interval_censored(artifact_dir, cutoff="2024-01-01") -> dict` writing `artifacts/merged/interval_censored.json` (keys: `n`, `n_negative_excluded`, `horizon_probs` at 7/30/90/180, `c_index`, `bias`) and `artifacts/merged/interval_censored_bias.png` (naive-KM vs life-table curves).

- [ ] **Step 1: Write the failing smoke test**

```python
# append to tests/test_interval_censored.py
def test_run_interval_censored_smoke(tmp_path):
    # minimal artifact dir: a PoC per_signal frame + a publication feature matrix
    art = tmp_path / "art"; (art / "merged").mkdir(parents=True)
    n = 200
    rng = np.random.default_rng(1)
    pub = pd.to_datetime("2020-01-01", utc=True)
    labels = pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(n)],
        "published": [pub] * n,
        "poc_duration_days": rng.integers(1, 400, n).astype(float),
        "poc_observed": rng.integers(0, 2, n).astype(bool),
        "poc_negative_duration_flag": [False] * n,
    })
    labels.to_parquet(art / "per_signal_labels.parquet", index=False)
    pd.DataFrame({"cve_id": labels["cve_id"], "cvss_v3_base": rng.random(n) * 10}).to_parquet(
        art / "publication_features.parquet", index=False)

    from scripts.build_interval_censored import run_interval_censored
    out = run_interval_censored(art, cutoff="2020-06-01")
    assert set(out) >= {"n", "n_negative_excluded", "horizon_probs", "c_index", "bias"}
    assert (art / "merged" / "interval_censored.json").exists()
    assert (art / "merged" / "interval_censored_bias.png").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py::test_run_interval_censored_smoke -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'scripts.build_interval_censored'`.

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/build_interval_censored.py
"""Fit the interval-censored (discrete-time) time-to-PoC model on real labels,
write metrics + the naive-KM-vs-life-table bias figure. CPU-only, memory-light."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from lifelines.utils import concordance_index

from temporal_exploit import interval_censored as ic

HORIZONS = (7.0, 30.0, 90.0, 180.0)


def run_interval_censored(artifact_dir: Path, cutoff: str = "2024-01-01") -> dict:
    artifact_dir = Path(artifact_dir)
    labels = pd.read_parquet(artifact_dir / "per_signal_labels.parquet")
    feats = pd.read_parquet(artifact_dir / "publication_features.parquet")
    df = labels.merge(feats, on="cve_id", how="inner")
    df["published"] = pd.to_datetime(df["published"], utc=True)

    n_neg = int(df["poc_negative_duration_flag"].sum())
    df = df[~df["poc_negative_duration_flag"] & (df["poc_duration_days"] > 0)].reset_index(drop=True)

    feature_cols = [c for c in feats.columns if c != "cve_id"]
    cut = pd.Timestamp(cutoff, tz="UTC")
    train, test = df[df["published"] < cut], df[df["published"] >= cut]

    model = ic.fit_discrete_time(
        train["poc_duration_days"].to_numpy(float),
        train["poc_observed"].to_numpy(int),
        train[feature_cols],
    )
    surv = model.survival_at(test[feature_cols], HORIZONS)
    horizon_probs = {int(h): float(np.mean(1.0 - surv[:, j])) for j, h in enumerate(HORIZONS)}
    risk = model.risk_scores(test[feature_cols])
    c_index = float(concordance_index(test["poc_duration_days"], -risk, test["poc_observed"]))

    bias = ic.bias_divergence(df["poc_duration_days"].to_numpy(float), df["poc_observed"].to_numpy(int))

    finite = [e for e in ic.HORIZON_BINS[1:] if np.isfinite(e)]
    naive = ic.naive_km_survival(df["poc_duration_days"], df["poc_observed"], finite)
    lifetable = ic.grouped_life_table(df["poc_duration_days"], df["poc_observed"])
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.step(finite, naive, where="post", label="naive exact-date KM")
    ax.step(finite, lifetable, where="post", label="grouped interval NPMLE (life-table)")
    ax.set_xlabel("days since publication"); ax.set_ylabel("S(t) — no PoC yet"); ax.legend()
    ax.set_title("PoC survival: exact-date bias vs interval-censored")
    (artifact_dir / "merged").mkdir(parents=True, exist_ok=True)
    fig.tight_layout(); fig.savefig(artifact_dir / "merged" / "interval_censored_bias.png", dpi=110)
    plt.close(fig)

    out = {"n": int(len(df)), "n_negative_excluded": n_neg,
           "horizon_probs": horizon_probs, "c_index": c_index, "bias": bias}
    (artifact_dir / "merged" / "interval_censored.json").write_text(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    print(json.dumps(run_interval_censored(Path("artifacts")), indent=2))
```

- [ ] **Step 4: Run smoke test, then the full suite**

Run: `.venv/bin/python -m pytest tests/test_interval_censored.py -q`
Expected: PASS (6 passed).
Run: `.venv/bin/python -m pytest -q`
Expected: full suite green (no regressions).

- [ ] **Step 5: Run on real data under a memory watch, then commit**

```bash
mkdir -p logs
/usr/bin/time -v .venv/bin/python scripts/build_interval_censored.py 2> logs/interval_censored_time.txt
grep -E "Maximum resident set size" logs/interval_censored_time.txt   # assert < 6 GB (6291456 KB)
cat artifacts/merged/interval_censored.json
git add src/temporal_exploit/interval_censored.py tests/test_interval_censored.py scripts/build_interval_censored.py
git commit -m "feat(interval-censored): real-data runner, metrics + bias figure (§3.2 A4)"
git push origin master
```

- [ ] **Step 6: Reverse-engineering / adversarial verification (≥5 loops; ≤2 subagents × 3–5 loops)**

Verify the flagship result before it feeds the writeup. Check, at minimum: (a) the head-to-head c-index vs the existing exact-date `xgb` first-weaponization baseline on the *same* split — does interval-censoring change ranking or only calibration? (b) the sign of the bias divergence matches the spec's falsifiable prediction (naive exact-date KM more pessimistic near batch dates); (c) leakage — confirm every `feature_col` is publication-time-knowable; (d) determinism — rerun, identical JSON; (e) sensitivity to bin edges (does the conclusion survive a finer/coarser grid?). Log findings to `docs/progress.md`; if the bias divergence ≈ 0, record the null honestly (the batch pathology does not materially bias survival) rather than forcing a positive result.

---

## Follow-on plans (out of scope for this plan)

- **Bucket B — §7 dashboard:** `scripts/build_dashboard.py → artifacts/dashboard.html`, consuming `triage`/`effort_metrics`/`decision_curve` + this model's exhibits. Own plan once A's artifacts exist.
- **Bucket C — research-narrative restructure (§2/3.1/4.1/5.1/6):** writeup consuming existing results + this model; web-verified citations. Own plan; not TDD-shaped.

## Self-Review

- **Spec coverage:** §3.2's two components (grouped-NPMLE bias exhibit ✔ A3; discrete-time covariate model ✔ A1+A2) and the runner/metrics/figure + RE (✔ A4) are all covered. Negative-duration handling ✔ A4 Step 3. Falsifiable prediction ✔ A4 Step 6. B and C explicitly deferred.
- **Placeholder scan:** none — every code step has complete, runnable code; every run step has an exact command + expected output.
- **Type consistency:** `bin_index`/`expand_person_period`/`HORIZON_BINS` (A1) → used verbatim in A2/A3/A4; `DiscreteTimeModel.feature_cols_`/`survival_at`/`risk_scores` (A2) → used in A4; `bias_divergence`/`naive_km_survival`/`grouped_life_table` (A3) → used in A4. `HORIZON_BINS` 7-bin tuple consistent throughout; eval `HORIZONS=(7,30,90,180)` are bin edges.
