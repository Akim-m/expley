# In-wild EPSS-Parity Head-to-Head — Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one consolidated, walk-forward scorecard that compares our in-wild model against EPSS on the **same target** (in-wild exploitation), at EPSS's own deployment metric (recall@top-1/5/10%) plus ranking (AUC) and precision-recall (PR-AUC), and honestly states where each wins.

**Architecture:** Reuse the existing proven machinery — `rolling_origin_backtest` already emits per-origin `horizon_auc` / `horizon_pr_auc` / `recall_at_top`, and `scripts/inwild_epss_ablation.py` already runs in-wild vs EPSS-only walk-forward with paired CIs. We make two small additions: (1) compute `recall_at_top` for multiple top-fracs (currently fixed at 10%), and (2) a single parity script + figure + writeup that unifies the arms (EPSS-only baseline, our structural model, and the state-aware composite) into the EPSS-parity deliverable.

**Tech Stack:** Python 3.12, pandas/numpy, lifelines + GPU XGBoost-AFT (existing models), matplotlib (figures), pytest (TDD). All inside the `inwild-epss-parity` worktree venv.

## Global Constraints

- **Leakage firewall:** features must be publication-time-knowable only; the in-wild label uses **event dates**, never snapshot presence. EPSS-at-publication is used ONLY as the baseline arm, never smuggled into our model. (Copied from spec.)
- **Timezone:** all date columns are `timestamp[ns, tz=UTC]`; normalize with `utc=True`, tz-aware snapshots/cutoffs.
- **Real names:** verified — in-wild labels = `cve_id, published, event_date, event_source, event_observed, duration_days, negative_duration_flag`; EPSS = `epss_at_publication, epss_percentile_at_publication, epss_at_publication_missing`; in-wild sources = `("kev","google_0day","vulncheck_kev","shadowserver","msrc")`.
- **DataFrame truthiness:** never use `df or other` — a DataFrame's truth value is ambiguous; use explicit `if x is None:`.
- **GPU-only models:** default modeling to GPU XGBoost-AFT (`model="xgb"`); do not add CPU rsf/gbm/cure.
- **RAM/VRAM budget:** ≤6–8 GB RAM / ≤7 GB VRAM; in-wild arms load only in-wild sources (skip the 188k-row PoC frame).
- **Workflow:** TDD (failing test → minimal impl → green → commit); ≥5 reverse-engineering rounds after any new function/model; frequent commits; push after each commit.

---

### Task 0: Wire the worktree to the shared data + confirm the analysis path runs

**Files:**
- Create (symlinks only, not committed): `dataset_extraction-20260608T210903Z-3-002`, `data`, `artifacts`, `epss_history-001.parquet` → the same paths under `/home/akim/Coding/Expl`.

**Interfaces:**
- Produces: a worktree where `scripts/inwild_epss_ablation.py` can find its inputs (gitignored data lives only in the main checkout).

- [ ] **Step 1: Symlink the gitignored data/artifacts from the main repo into the worktree**

```bash
cd /home/akim/Coding/Expl/.claude/worktrees/inwild-epss-parity
MAIN=/home/akim/Coding/Expl
for p in dataset_extraction-20260608T210903Z-3-002 data artifacts epss_history-001.parquet; do
  [ -e "$p" ] || ln -s "$MAIN/$p" "$p"
done
ls -ld dataset_extraction-* data artifacts epss_history-001.parquet
```

Expected: four symlinks resolving into `/home/akim/Coding/Expl/...`. (These are local-only; `.git/info/exclude` already hides `.claude/worktrees/`, and symlinks to gitignored paths are themselves ignored.)

- [ ] **Step 2: Confirm the existing in-wild vs EPSS-only ablation runs here (baseline of the analysis path)**

Run: `.venv/bin/python scripts/inwild_epss_ablation.py 2>&1 | tail -8`
Expected: prints `full vs EPSS-only PR-AUC@30/90` deltas and writes `artifacts/inwild_epss_ablation.json` — confirms data wiring + GPU model work before we build on them.

- [ ] **Step 3: Commit (no repo files changed — record the verified baseline instead)**

No commit needed (only symlinks, which are untracked). Note the ablation output in the task log and proceed.

---

### Task 1: Multi-k `recall_at_top` in the backtest (EPSS's deployment metric)

**Files:**
- Modify: `src/temporal_exploit/backtest.py` (`operational_metrics`, the per-origin append in `rolling_origin_backtest`, and `_aggregate`)
- Test: `tests/test_backtest_recall_multi.py`

**Interfaces:**
- Consumes: `operational_metrics(risk, test_frame, horizons, top_frac=0.1, top_fracs=(0.01,0.05,0.10))`
- Produces: each per-origin dict and the `aggregate` gain a new key `recall_at_top_by_frac = {"<frac>": {"<horizon>": recall}}`; the existing `recall_at_top` (top_frac=0.1) is unchanged for back-compat.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_backtest_recall_multi.py
import numpy as np
import pandas as pd
from temporal_exploit.backtest import operational_metrics


def test_recall_at_top_by_frac_matches_known_ranking():
    # 10 CVEs ranked by risk = index (9 = highest). The 3 true events sit at the
    # very top of the ranking (indices 7,8,9), each weaponizing within 30 days.
    risk = np.arange(10, dtype=float)
    dur = np.array([100, 100, 100, 100, 100, 100, 100, 5, 5, 5], dtype=float)
    obs = np.array([0, 0, 0, 0, 0, 0, 0, 1, 1, 1], dtype=bool)
    frame = pd.DataFrame({"duration_days": dur, "event_observed": obs})

    out = operational_metrics(risk, frame, horizons=[30], top_fracs=(0.1, 0.3))

    # top-10% = 1 flagged CVE (index 9, an event) -> caught 1 of 3 events
    assert out["recall_at_top_by_frac"]["0.1"]["30"] == 1 / 3
    # top-30% = 3 flagged CVEs (indices 7,8,9 = all 3 events) -> caught 3 of 3
    assert out["recall_at_top_by_frac"]["0.3"]["30"] == 1.0
    # back-compat: the single-frac recall_at_top (default 0.1) is unchanged
    assert out["recall_at_top"]["30"] == 1 / 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_backtest_recall_multi.py -v`
Expected: FAIL — `KeyError: 'recall_at_top_by_frac'` (the key does not exist yet).

- [ ] **Step 3: Rewrite `operational_metrics` to compute recall for multiple fracs**

Replace the body of `operational_metrics` (currently `backtest.py:150-173`) with:

```python
def operational_metrics(risk, test_frame, horizons, top_frac: float = 0.1,
                        top_fracs: tuple = (0.01, 0.05, 0.10)) -> dict:
    """Decision-relevant metrics for a timeline. recall_at_top: of CVEs that
    actually weaponized within h, the fraction flagged in the top-`top_frac` by
    predicted risk. recall_at_top_by_frac: the same recall computed at several
    top-fracs (EPSS's deployment operating points). lead_time_days: median actual
    time-to-weaponization among the flagged weaponizers."""
    risk = np.asarray(risk, float)
    dur = test_frame["duration_days"].to_numpy(float)
    obs = test_frame["event_observed"].to_numpy(bool)
    order = np.argsort(risk)[::-1]

    def _recall(frac):
        n_top = max(1, int(round(len(risk) * frac)))
        top = np.zeros(len(risk), dtype=bool)
        top[order[:n_top]] = True
        rec = {}
        for h in horizons:
            weap_by_h = obs & (dur <= h)
            n = int(weap_by_h.sum())
            if n:
                rec[str(h)] = float((weap_by_h & top).sum() / n)
        return rec, top

    recall, top = _recall(top_frac)
    recall_by_frac = {f"{f:g}": _recall(f)[0] for f in top_fracs}
    caught = dur[obs & top]
    return {
        "recall_at_top": recall,
        "recall_at_top_by_frac": recall_by_frac,
        "lead_time_days": float(np.median(caught)) if caught.size else None,
        "top_frac": top_frac,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_backtest_recall_multi.py -v`
Expected: PASS.

- [ ] **Step 5: Thread the new field through `rolling_origin_backtest` and `_aggregate`**

In the per-origin append inside `rolling_origin_backtest` (the dict around `backtest.py:278-291`, which already has `"recall_at_top": op["recall_at_top"],`), add immediately after that line:

```python
                "recall_at_top_by_frac": op["recall_at_top_by_frac"],
```

In `_aggregate` (`backtest.py:411`), after the existing `for metric in (...)` loop and before the `leads = [...]` line, add:

```python
    agg["recall_at_top_by_frac"] = {}
    fracs = sorted({f for o in per_origin for f in o.get("recall_at_top_by_frac", {})})
    for f in fracs:
        agg["recall_at_top_by_frac"][f] = {}
        for h in horizons:
            vals = [o["recall_at_top_by_frac"][f].get(str(h))
                    for o in per_origin
                    if o.get("recall_at_top_by_frac", {}).get(f, {}).get(str(h)) is not None]
            if vals:
                agg["recall_at_top_by_frac"][f][str(h)] = {
                    "mean": float(np.mean(vals)), "median": float(np.median(vals)),
                    "sd": float(np.std(vals)), "n": len(vals),
                }
```

- [ ] **Step 6: Run the full suite to confirm no regression (existing consumers read the unchanged `recall_at_top`)**

Run: `.venv/bin/python -m pytest -q 2>&1 | tail -3`
Expected: 335 passed (334 prior + 1 new), 4 skipped. If any existing backtest test fails, the per-origin/aggregate change broke back-compat — re-check that `recall_at_top` was left untouched.

- [ ] **Step 7: Commit**

```bash
git add src/temporal_exploit/backtest.py tests/test_backtest_recall_multi.py
git commit -m "feat(backtest): multi-k recall_at_top (EPSS operating points) — back-compat preserved"
git push
```

---

### Task 2: The EPSS-parity head-to-head script (same target, two core arms)

**Files:**
- Create: `scripts/inwild_epss_parity.py`
- Output: `artifacts/inwild_epss_parity.json`

**Interfaces:**
- Consumes: `rolling_origin_backtest(...)` with `label_set="in_wild"`, `make_origins`, `paired_origin_deltas`, the new `aggregate["recall_at_top_by_frac"]`, and `IN_WILD_SOURCES` / `in_wild_clock_start` / `load_optional_event` from `cli`.
- Produces: a JSON scorecard with `per_arm` (auc_30/90, pr_auc_30, recall_at_top_30 at k∈{1,5,10}%, test_events_total) and `structural_vs_epss_only` paired deltas + CIs.

- [ ] **Step 1: Write the parity script (mirrors the proven `inwild_epss_ablation.py` structure)**

```python
# scripts/inwild_epss_parity.py
"""EPSS-parity head-to-head: our in-wild model vs EPSS on the SAME target.

Target = in-wild exploitation (KEV / Google 0-day / VulnCheck) — exactly what EPSS
predicts. On identical walk-forward origins, reports for two arms:
  - epss_only  : the EPSS-at-publication baseline (what EPSS alone gives you)
  - structural : our publication-time structural model with NO EPSS (deployable config)
Metrics: ranking AUC@30/90, PR-AUC@30, and EPSS's deployment metric recall@top-1/5/10%@30.
Prints an honest verdict (where EPSS wins, where we win) with paired CIs on AUC/PR-AUC.
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")  # VulnCheck-expanded in-wild events
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
KS = (0.01, 0.05, 0.10)
MODEL = "xgb"

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:  # in-wild only; skip the 188k-row PoC frame
        continue
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
print(f"in-wild sources loaded={sorted(event_frames)}", flush=True)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
epss_cols = epss_feature_columns(features_full.columns)
meta = [c for c in ("cve_id", "published") if c in features_full.columns]
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))

arms = {
    "epss_only": features_full[meta + epss_cols],
    "structural": features_full.drop(columns=epss_cols),
}
res = {}
for tag, feats in arms.items():
    res[tag] = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL,
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    )


def _recall_table(agg):
    rb = agg.get("recall_at_top_by_frac", {})
    return {f"{k:g}": rb.get(f"{k:g}", {}).get("30", {}).get("mean") for k in KS}


def _auc(agg, metric, h):
    return agg.get(metric, {}).get(str(h), {}).get("mean")


out = {
    "target": "in_wild (KEV / Google 0-day / VulnCheck) — same target as EPSS",
    "model": MODEL, "epss_columns": epss_cols, "n_origins": len(origins),
    "per_arm": {
        tag: {
            "auc_30": _auc(r["aggregate"], "horizon_auc", 30),
            "auc_90": _auc(r["aggregate"], "horizon_auc", 90),
            "pr_auc_30": _auc(r["aggregate"], "horizon_pr_auc", 30),
            "recall_at_top_30": _recall_table(r["aggregate"]),
            "test_events_total": r["aggregate"]["test_events_total"],
        }
        for tag, r in res.items()
    },
    "structural_vs_epss_only": {
        f"{m}_{h}": paired_origin_deltas(res["structural"], res["epss_only"], m, h)
        for m in ("horizon_auc", "horizon_pr_auc") for h in (30, 90)
    },
}
Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/inwild_epss_parity.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True, default=str)

s, e = out["per_arm"]["structural"], out["per_arm"]["epss_only"]
d = out["structural_vs_epss_only"]["horizon_auc_30"]
print(f"\n=== EPSS parity (same in-wild target, {len(origins)} origins, {s['test_events_total']} test events) ===")
print(f"AUC@30   structural {s['auc_30']:.3f}  vs EPSS-only {e['auc_30']:.3f}   paired Δ {d['mean_delta']:+.3f} CI {d['ci95']}")
for k in KS:
    kk = f"{k:g}"
    sv, ev = s["recall_at_top_30"][kk], e["recall_at_top_30"][kk]
    winner = "structural" if (sv or 0) > (ev or 0) else "EPSS"
    print(f"recall@top-{k:.0%}@30   structural {sv}  vs EPSS-only {ev}   -> {winner} wins")
print("wrote artifacts/inwild_epss_parity.json")
```

- [ ] **Step 2: Run the parity script (integration smoke + result capture)**

Run: `.venv/bin/python scripts/inwild_epss_parity.py 2>&1 | tail -12`
Expected: writes `artifacts/inwild_epss_parity.json` and prints the verdict. Sanity against prior results — structural AUC@30 should land ≈0.80+ and EPSS-only ≈0.60 (structural wins ranking); EPSS is expected to win or tie at recall@top-1%/5% (its home turf). **Record the actual numbers; if structural AUC@30 < EPSS-only, stop and investigate (it would contradict every prior in-wild result).**

- [ ] **Step 3: Verify the JSON structure**

Run:
```bash
.venv/bin/python -c "import json; d=json.load(open('artifacts/inwild_epss_parity.json')); \
print(sorted(d)); print(sorted(d['per_arm'])); print(d['per_arm']['structural']['recall_at_top_30'])"
```
Expected: top keys include `per_arm`, `structural_vs_epss_only`, `target`; `per_arm` has `epss_only` and `structural`; the recall table has keys `0.01`, `0.05`, `0.1`.

- [ ] **Step 4: Commit**

```bash
git add scripts/inwild_epss_parity.py
git commit -m "feat(parity): in-wild vs EPSS head-to-head on the same target (AUC/PR-AUC/recall@top-k, walk-forward)"
git push
```

---

### Task 3: The state-aware composite arm (the "beat EPSS as a system" deliverable)

**Files:**
- Create: `scripts/inwild_epss_parity_composite.py` (reuses the proven logic in `scripts/defender_score.py`)
- Output: `artifacts/inwild_epss_parity_composite.json`

**Interfaces:**
- Consumes: `triage.operating_points(risk, dur, ev, horizon, ks=(0.01,0.05,0.10))`, `labels.build_transition_labels(corpus, frames, snap, from_source="poc", to_source="kev", competing_sources=...)`, `modeling.prepare_modeling_frame` / `_risk_scores`, a quantile time-split.
- Produces: JSON comparing operating points of `epss_only`, `structural`, and `composite` (structural at PUBLISHED + PoC→KEV escalation at POC_PRESENT) at the locked 70/30 split.

> **Reference:** `scripts/defender_score.py` already computes `state_published_epss_only` (EPSS operating points) and `state_poc_present_to_kev` (the PoC→KEV escalation). This task adapts that proven script to emit a single side-by-side EPSS-vs-composite JSON. Follow its structure for the model fits and split; do not re-derive the transition-label plumbing.

- [ ] **Step 1: Write the composite parity script**

```python
# scripts/inwild_epss_parity_composite.py
"""Composite ("beat EPSS as a system") arm of the EPSS-parity deliverable.

EPSS is a single publication-time score. Our composite is STATE-AWARE: at PUBLISHED
it uses the structural first-weaponization risk; once a PoC exists it ESCALATES to the
sharp PoC->KEV in-wild model (the signal EPSS cannot see). This reports recall@top-k%
operating points for epss_only vs structural vs composite at the locked 70/30 split.
Mirrors scripts/defender_score.py (the proven state-aware computation)."""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import build_transition_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import _fit_model as _fit  # use the same fitter defender_score uses
from temporal_exploit.modeling import _risk_scores, prepare_modeling_frame
from temporal_exploit.triage import operating_points

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAP, H = "2026-03-14", 90
feats = pd.read_parquet("artifacts/merged/publication_features.parquet")
corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])

# STATE 1 — publication-time first-weaponization: structural model vs EPSS-only
fw = pd.read_parquet("artifacts/merged/modeling_labels.parquet")
frame = prepare_modeling_frame(fw, feats)
cut = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
tr = frame[pd.to_datetime(frame["published"], utc=True) <= cut]
te = frame[pd.to_datetime(frame["published"], utc=True) > cut]
model = _fit("xgb", tr)
risk_struct = _risk_scores(model, te[list(model.feature_cols_)].astype(float), "xgb")
dur, ev = te["duration_days"].to_numpy(float), te["event_observed"].to_numpy(bool)
epss_only = te["epss_at_publication"].to_numpy(float)

results = {
    "state_published_structural": operating_points(risk_struct, dur, ev, H),
    "state_published_epss_only": operating_points(epss_only, dur, ev, H),
}

# STATE 2 — PoC-present escalation: the sharp PoC->KEV in-wild model
frames = {}
for s in ["poc", "kev", "metasploit", "nuclei"]:
    pn, dc = EVENT_SOURCES[s]
    fr = load_optional_event(OUT_DIR, pn, dc)
    if fr is not None:
        frames[s] = (fr, dc)
lab = build_transition_labels(corpus, frames, SNAP, from_source="poc", to_source="kev",
                              competing_sources=("metasploit", "nuclei"))
tf = prepare_modeling_frame(lab, feats)
cut2 = pd.to_datetime(tf["published"], utc=True).quantile(0.70)
tr2 = tf[pd.to_datetime(tf["published"], utc=True) <= cut2]
te2 = tf[pd.to_datetime(tf["published"], utc=True) > cut2]
m2 = _fit("xgb", tr2)
risk_poc2kev = _risk_scores(m2, te2[list(m2.feature_cols_)].astype(float), "xgb")
dur2, ev2 = te2["duration_days"].to_numpy(float), te2["event_observed"].to_numpy(bool)
results["state_poc_present_to_kev"] = operating_points(risk_poc2kev, dur2, ev2, 90)

Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/inwild_epss_parity_composite.json", "w") as fh:
    json.dump(results, fh, indent=2, sort_keys=True, default=str)
print("=== STATE 1 (PUBLISHED): structural vs EPSS-only recall@top-k ===")
for k in ("0.01", "0.05", "0.1"):
    s = results["state_published_structural"][k]["recall"]
    e = results["state_published_epss_only"][k]["recall"]
    print(f"  top-{k}: structural {s}  vs EPSS {e}")
print("=== STATE 2 (POC_PRESENT): PoC->KEV escalation (EPSS has no state) ===")
for k in ("0.01", "0.05", "0.1"):
    print(f"  top-{k}: {results['state_poc_present_to_kev'][k]['recall']}")
print("wrote artifacts/inwild_epss_parity_composite.json")
```

> **Note on names to verify before running:** confirm the fitter helper name in `modeling.py` (`defender_score.py` imports it as `_fit` via `_fit_model`); if the symbol differs, match `defender_score.py`'s import exactly. Confirm `operating_points` returns a dict keyed by `"0.01"/"0.05"/"0.1"` each with a `"recall"` field (triage.py:147-173).

- [ ] **Step 2: Verify the fitter/return-shape names against the codebase, then run**

Run:
```bash
.venv/bin/python -c "import temporal_exploit.modeling as m; print([n for n in dir(m) if 'fit' in n.lower()])"
.venv/bin/python scripts/inwild_epss_parity_composite.py 2>&1 | tail -12
```
Expected: prints STATE 1 (structural vs EPSS recall@top-k) and STATE 2 (PoC→KEV recall) and writes the JSON. Expected pattern from `docs/defender_interpretation_2026-06.md`: **EPSS wins/ties STATE 1 top-k**, and STATE 2 PoC→KEV recall@top-10% ≈ 0.5 — the composite's value is the escalation EPSS cannot give.

- [ ] **Step 3: Commit**

```bash
git add scripts/inwild_epss_parity_composite.py
git commit -m "feat(parity): state-aware composite arm (structural + PoC->KEV escalation) vs EPSS operating points"
git push
```

---

### Task 4: Parity figure + writeup + README/progress update

**Files:**
- Modify: `scripts/build_report_figures.py` (add `fig_epss_parity`)
- Create: `docs/inwild_epss_parity_2026-06.md`
- Modify: `README.md` (add a parity bullet under "Results at a glance"), `docs/progress.md` (detailed entry)

**Interfaces:**
- Consumes: `artifacts/inwild_epss_parity.json` + `artifacts/inwild_epss_parity_composite.json` (numbers transcribed into the figure, matching the existing figures' grounded-values convention).

- [ ] **Step 1: Add the parity figure function**

In `scripts/build_report_figures.py`, add a `fig_epss_parity()` that draws two panels from the recorded JSON numbers — left: AUC@30 + recall@top-1/5/10%@30 grouped bars (structural vs EPSS-only), right: the composite STATE-2 PoC→KEV recall — titled "Same target as EPSS: we win ranking, EPSS wins top-k precision; the win is the escalation." Register it in `__main__` and save `docs/figures/fig_epss_parity.png`. (Follow the existing `fig_two_heads` / `fig_operating_points` style and palette.)

- [ ] **Step 2: Run the figure builder; confirm the PNG is written**

Run: `.venv/bin/python scripts/build_report_figures.py 2>&1 | grep parity`
Expected: `WROTE .../docs/figures/fig_epss_parity.png`.

- [ ] **Step 3: Write the writeup `docs/inwild_epss_parity_2026-06.md`**

One page: the target-mismatch framing (first-weap PoC vs in-wild = EPSS's target), the method (same target, walk-forward, AUC/PR-AUC/recall@top-k), the headline numbers from both JSONs, and the honest verdict (where EPSS wins, where we win, and that the composite's value is the PoC→KEV escalation EPSS can't provide). Embed `docs/figures/fig_epss_parity.png`.

- [ ] **Step 4: Update README + progress**

Add a "Results at a glance" bullet linking the parity figure + writeup, and a detailed `docs/progress.md` entry. Keep both in sync (project rule).

- [ ] **Step 5: Commit**

```bash
git add scripts/build_report_figures.py docs/figures/fig_epss_parity.png docs/inwild_epss_parity_2026-06.md README.md docs/progress.md
git commit -m "docs(parity): EPSS-parity figure + writeup + README/progress"
git push
```

---

## Self-Review

**1. Spec coverage:** spec goal 1 (elevate in-wild target) → Tasks 2/3 use `label_set="in_wild"` as the primary target; goal 2 (parity harness: same target/estimand/metric) → Task 1 (recall@top-k) + Task 2 (AUC/PR-AUC/recall walk-forward); goal 3 (three arms incl. composite) → Tasks 2 (epss_only, structural) + 3 (composite); goal 4 (label growth) → **explicitly deferred to the Phase-2 plan** (gated on a VulnCheck token / GreyNoise research grant — see handoff). Leakage/tz/real-names constraints → Global Constraints + verified schemas. No spec requirement for Phase 1 is unaddressed.

**2. Placeholder scan:** no TBD/TODO; every code step carries complete code. Task 3 flags two names to confirm against the codebase before running (the `modeling` fitter symbol and the `operating_points` return shape) — these are verification steps, not placeholders, because Task 3 deliberately reuses `defender_score.py`'s proven imports.

**3. Type consistency:** `recall_at_top_by_frac` keys are `f"{f:g}"` (→ `"0.01"`,`"0.05"`,`"0.1"`) consistently in Task 1 (producer), Task 2 (`_recall_table` consumer), and Task 3/4 (`"0.01"/"0.05"/"0.1"`). `operational_metrics` keeps the original `recall_at_top` so every existing consumer (e.g. `scripts/operating_points.py`) is unbroken. Backtest call signature matches `inwild_epss_ablation.py` exactly.

## Phase 2 (separate plan, gated on credentials)

Not in this plan — gets its own once a token exists. Concrete from the API research:
- **VulnCheck KEV community (do first):** extend `fetch/vulncheck.py` to pull `GET /v3/backup/vulncheck-kev` (`Authorization: Bearer $VULNCHECK_API_TOKEN`, free token, 1000 req/min), event date = `min(date_added, min(vulncheck_reported_exploitation[].date_added))`, filter `>= published`; merge into in-wild events; re-run Task 2. ~+1,000–1,700 in-wild CVEs.
- **GreyNoise (gated, prospective-only):** needs the free Research Community grant (manual approval) for GNQL; derive in-wild date = `min(first_seen)` over `cve:` IPs, but the association is a rolling ~90-day window → forward-looking stream, **weak for historical backfill**. Lower priority.
