"""A1 re-metric: restate the EPSS-parity headline in the field's idiom.

Mirrors scripts/inwild_epss_parity.py's exact arms (structural xgb with NO EPSS
data vs raw epss_percentile_at_publication via score_col) on identical origins,
then reports what the field actually uses (EPSS/FIRST/Coalition idiom):
  - coverage/effort curves: recall of within-h events when triaging the top-f
    fraction, over a dense effort grid, with paired per-origin deltas + CIs;
  - POOLED stratified-bootstrap PR-AUC CIs per arm (Boyd 2013) — the noise
    band the "PR-AUC tied" claim lives inside;
  - the aggregated (caveated, secondary) IPCW c-index per arm;
  - an explicit EPSS-version stamp (history file predates EPSS v5, 2026-06-15).
Outputs artifacts/inwild_remetric.json + docs/figures/fig_coverage_effort.png.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import (
    make_origins,
    paired_origin_deltas,
    rolling_origin_backtest,
)
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.effort_metrics import pooled_bootstrap_pr_auc, recall_by_frac_deltas
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
EFFORT_GRID = (0.005, 0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.30)
CURVE_HORIZONS = (30, 90)
MODEL = "xgb"
EPSS_VERSION_NOTE = (
    "EPSS scores come from the local epss_history file (v3/v4-era through the "
    "2026-03-14 snapshot); EPSS v5 (released 2026-06-15) is NOT in this history — "
    "every comparison here is versus pre-v5 EPSS."
)

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:
        continue
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
print(f"in-wild sources loaded={sorted(event_frames)}", flush=True)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
epss_cols = epss_feature_columns(features_full.columns)
_STATIC = {"epss_at_publication", "epss_percentile_at_publication", "epss_at_publication_missing"}
assert set(epss_cols) <= _STATIC, f"expected only static EPSS cols, got {epss_cols}"
structural_features = features_full.drop(columns=[c for c in epss_cols
                                                  if c != "epss_percentile_at_publication"])
# structural arm must see NO EPSS data (standing directive); the score column
# stays in the frame only for the score_col passthrough arm.
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))
common = dict(
    snapshot_date=SNAPSHOT, origins=origins, label_set="in_wild",
    horizons=HORIZONS, clock_start=clock_start,
    top_fracs=EFFORT_GRID, keep_scores=True,
)

print("arm 1/2: structural xgb (EPSS-free) ...", flush=True)
structural = rolling_origin_backtest(
    corpus, event_frames,
    structural_features.drop(columns=["epss_percentile_at_publication"]),
    model=MODEL, **common,
)
print("arm 2/2: raw EPSS score passthrough ...", flush=True)
epss_arm = rolling_origin_backtest(
    corpus, event_frames, structural_features,
    score_col="epss_percentile_at_publication", **common,
)


def pooled_pr_auc(res, horizon):
    """Pooled PR-AUC + stratified bootstrap CI over the horizon subcohort
    (drop rows censored before h — the evaluator's 'known' semantics)."""
    risk, dur, obs = [], [], []
    for o in res["per_origin"]:
        s = o["scores"]
        risk += s["risk"]; dur += s["duration_days"]; obs += s["event_observed"]
    risk = np.asarray(risk); dur = np.asarray(dur); obs = np.asarray(obs, bool)
    known = (dur > horizon) | obs
    y = obs & (dur <= horizon)
    return pooled_bootstrap_pr_auc(y[known], risk[known], n_boot=1000, seed=0)


def curve(res, horizon):
    """Mean coverage at each effort level (aggregate over origins)."""
    a = res["aggregate"]["recall_at_top_by_frac"]
    return {f: a.get(f"{f:g}", {}).get(str(horizon), {}).get("mean") for f in EFFORT_GRID}


out = {
    "config": {"model": MODEL, "origins": origins, "effort_grid": list(EFFORT_GRID),
               "structural_arm": "publication features, NO EPSS columns",
               "epss_arm": "raw epss_percentile_at_publication via score_col"},
    "epss_version_note": EPSS_VERSION_NOTE,
    "coverage_effort": {
        str(h): {
            "structural": curve(structural, h),
            "epss_score": curve(epss_arm, h),
            "paired_deltas": {
                f"{f:g}": recall_by_frac_deltas(structural, epss_arm, f"{f:g}", h)
                for f in EFFORT_GRID
            },
        } for h in CURVE_HORIZONS
    },
    "pooled_pr_auc": {
        str(h): {"structural": pooled_pr_auc(structural, h),
                 "epss_score": pooled_pr_auc(epss_arm, h)}
        for h in CURVE_HORIZONS
    },
    "paired_pr_auc_origin_deltas": {
        str(h): paired_origin_deltas(structural, epss_arm, "horizon_pr_auc", h)
        for h in CURVE_HORIZONS
    },
    "c_index_ipcw": {
        "structural": structural["aggregate"].get("c_index_ipcw"),
        "epss_score": epss_arm["aggregate"].get("c_index_ipcw"),
    },
    "auc_headline_check": {  # must reproduce the parity artifact to rounding
        str(h): paired_origin_deltas(structural, epss_arm, "horizon_auc", h)
        for h in (30, 90)
    },
    "n_test_events_total": structural["aggregate"]["test_events_total"],
}

Path("artifacts/inwild_remetric.json").write_text(json.dumps(out, indent=1))
print("wrote artifacts/inwild_remetric.json", flush=True)

# ------------------------------------------------------------------ figure
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
for ax, h in zip(axes, CURVE_HORIZONS):
    ce = out["coverage_effort"][str(h)]
    xs = [f * 100 for f in EFFORT_GRID]
    ax.plot(xs, [ce["structural"][f] for f in EFFORT_GRID], "o-",
            color="#1a3a5c", label="structural (EPSS-free)")
    ax.plot(xs, [ce["epss_score"][f] for f in EFFORT_GRID], "s--",
            color="#c0392b", label="raw EPSS score")
    ax.set_title(f"coverage vs effort — {h}d horizon")
    ax.set_xlabel("effort: top-% of list triaged")
    ax.set_xscale("log")
    ax.grid(alpha=0.3)
axes[0].set_ylabel("coverage: share of within-h exploited CVEs caught")
axes[0].legend(loc="upper left", fontsize=8)
fig.suptitle("In-wild coverage/effort curves (15-origin walk-forward; pre-v5 EPSS)", fontsize=10)
fig.tight_layout()
fig.savefig("docs/figures/fig_coverage_effort.png", dpi=150)
print("wrote docs/figures/fig_coverage_effort.png", flush=True)

# ------------------------------------------------------------------ verdict
for h in CURVE_HORIZONS:
    pp = out["pooled_pr_auc"][str(h)]
    print(f"\nh={h}d pooled PR-AUC: structural {pp['structural']['pr_auc']:.4f} "
          f"{pp['structural']['ci95']} vs EPSS {pp['epss_score']['pr_auc']:.4f} "
          f"{pp['epss_score']['ci95']}")
    for f in (0.01, 0.05, 0.10):
        d = out["coverage_effort"][str(h)]["paired_deltas"][f"{f:g}"]
        print(f"  coverage@{f:.0%}: Δ{d['mean_delta']:+.3f} ci95={d['ci95']} win={d['win_frac']:.2f}")
print(f"\nAUC headline check @30: {out['auc_headline_check']['30']['mean_delta']:+.4f} "
      f"(parity artifact: +0.1001)")
