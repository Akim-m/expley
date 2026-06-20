"""Instant-head incentive ablation: do the attacker-incentive flags add signal over the
EPSS static floor at t=0 (publication), where the EPSS *trajectory* does NOT yet exist?

F6 showed the incentive flags are redundant WITH the EPSS landmark trajectory on the
in-wild head. t=0 (and the <=7d window that closes before EPSS updates) is the only place
they can be non-redundant. Runs full / no_incentive / epss_floor_only at the instant head
(publication-only view, no landmark) over short horizons, on the powered first_weaponization
head (190k events) and the in_wild head (directional). GPU xgb-AFT.
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
    EVENT_FEATURE_COLUMNS,
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.incentive_features import (
    build_incentive_features,
    incentive_feature_columns,
)
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (1, 3, 7, 30, 90)
MODEL = "xgb"

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
# first_weaponization needs all event sources; load fresh (data/live) with handover fallback
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    extra = EVENT_FEATURE_COLUMNS.get(source, ())
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col, extra)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col, extra)
    if frame is not None:
        event_frames[source] = (frame, date_col)
print(f"sources loaded={sorted(event_frames)}", flush=True)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
# the prebuilt matrix predates the incentive features (commit 4c66a11) -> build + merge now
if not incentive_feature_columns(features_full.columns):
    corpus_inc = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "cvss_v3_vector"])
    features_full = features_full.merge(build_incentive_features(corpus_inc), on="cve_id", how="left")
    del corpus_inc
epss_cols = epss_feature_columns(features_full.columns)
incentive_cols = incentive_feature_columns(features_full.columns)
meta = [c for c in ("cve_id", "published") if c in features_full.columns]
print(f"epss_cols={epss_cols}\nincentive_cols={incentive_cols}", flush=True)

origins = make_origins(SNAPSHOT, START, min_followup_days=180)


def _features_for(tag):
    if tag == "no_incentive":
        return features_full.drop(columns=incentive_cols)
    if tag == "epss_floor_only":
        return features_full[meta + epss_cols]
    return features_full


def _run(label_set, tag, clock_start):
    feats = _features_for(tag)
    res = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL, label_set=label_set,
        horizons=HORIZONS, clock_start=clock_start, feature_view="publication_only",
    )
    if feats is not features_full:
        del feats
    return res


out = {}
for label_set in ("first_weaponization", "in_wild"):
    clock = (
        in_wild_clock_start(tuple(s for s in event_frames if s in IN_WILD_SOURCES))
        if label_set == "in_wild"
        else None
    )
    res = {tag: _run(label_set, tag, clock) for tag in ("full", "no_incentive", "epss_floor_only")}
    out[label_set] = {
        "per_model": {tag: r["aggregate"] for tag, r in res.items()},
        "full_vs_epss_floor": {
            f"pr_auc_{h}": paired_origin_deltas(res["full"], res["epss_floor_only"], "horizon_pr_auc", h)
            for h in (7, 30)
        },
        "full_vs_no_incentive": {
            f"pr_auc_{h}": paired_origin_deltas(res["full"], res["no_incentive"], "horizon_pr_auc", h)
            for h in (7, 30)
        },
    }
    for h in (7, 30):
        d = out[label_set]["full_vs_no_incentive"][f"pr_auc_{h}"]
        helps = d["ci95"] is not None and d["ci95"][0] > 0
        print(
            f"  [{label_set}] incentive marginal PR-AUC@{h}: delta {d['mean_delta']:+.4f} "
            f"CI {d['ci95']} n={d['n_paired']} -> {'helps' if helps else 'within error'}",
            flush=True,
        )

Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/instant_incentive_ablation.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/instant_incentive_ablation.json", flush=True)
