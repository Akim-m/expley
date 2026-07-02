"""EPSS circularity control, LANDMARK regime: does the in-wild model beat the STRONG
EPSS baseline -- the predictive trajectory (~0.63-0.68 AUC) -- not just the static
publication floor (~0.52)?

Builds the EPSS landmark trajectory (velocity/std/mean/days-to-threshold) as-of
published+L via one fused EPSS scan, merges it into the feature matrix, and runs the
full / no_epss / epss_only ablation in the LANDMARK regime: rolling_origin_backtest
with landmark_days=L applies restart_clock per origin so the trajectory is leakage-safe.
GPU xgb-AFT, in-wild labels (VulnCheck from data/live). This is the proper bar the
static-floor ablation (scripts/inwild_epss_ablation.py) could not test.
"""
import json
from pathlib import Path

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
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.landmark import load_epss_at_landmark
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
ARTIFACT_DIR = "artifacts/bt_epss"
EPSS_PATH = "epss_history-001.parquet"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
LANDMARK, MODEL = 30, "xgb"

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
missing = [s for s in IN_WILD_SOURCES if s not in event_frames]
print(f"in-wild sources loaded={sorted(event_frames)} missing={missing}", flush=True)

# publication features + the landmark EPSS trajectory (one fused EPSS scan)
features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
print(f"loading landmark EPSS trajectory (L={LANDMARK}; cache: artifacts/, else stream) ...", flush=True)
lm_epss = load_epss_at_landmark(corpus, EPSS_PATH, LANDMARK, snapshot_date=SNAPSHOT, artifact_dir="artifacts")
features_full = features_full.merge(lm_epss, on="cve_id", how="left")
del lm_epss
epss_cols = epss_feature_columns(features_full.columns)  # static publication + landmark trajectory
meta = [c for c in ("cve_id", "published") if c in features_full.columns]
print(f"model={MODEL} landmark={LANDMARK} EPSS columns (incl. trajectory)={epss_cols}", flush=True)

origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))


def _features_for(tag):
    if tag == "no_epss":
        return features_full.drop(columns=epss_cols)
    if tag == "epss_only":
        return features_full[meta + epss_cols]
    return features_full


res = {}
for tag in ("full", "no_epss", "epss_only"):
    feats = _features_for(tag)
    res[tag] = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL, label_set="in_wild",
        horizons=HORIZONS, clock_start=clock_start, landmark_days=LANDMARK,
    )
    if feats is not features_full:
        del feats

out = {
    "model": MODEL,
    "landmark_days": LANDMARK,
    "epss_columns": epss_cols,
    "per_model": {tag: r["aggregate"] for tag, r in res.items()},
    "full_vs_epss_only": {
        f"{m}_{h}": paired_origin_deltas(res["full"], res["epss_only"], m, h)
        for m in ("horizon_pr_auc", "horizon_auc") for h in (30, 90)
    },
    "full_vs_no_epss": {
        f"{m}_{h}": paired_origin_deltas(res["full"], res["no_epss"], m, h)
        for m in ("horizon_pr_auc", "horizon_auc") for h in (30, 90)
    },
}
for h in (30, 90):
    d = out["full_vs_epss_only"][f"horizon_pr_auc_{h}"]
    beats = d["ci95"] is not None and d["ci95"][0] > 0
    print(
        f"  full vs STRONG EPSS-only (landmark) PR-AUC@{h}: delta {d['mean_delta']:+.4f} "
        f"CI {d['ci95']} n={d['n_paired']} -> {'beats EPSS-only' if beats else 'within error'}",
        flush=True,
    )
Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/inwild_epss_ablation_landmark.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/inwild_epss_ablation_landmark.json", flush=True)
