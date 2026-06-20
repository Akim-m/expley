"""Operating-points table: instant (L=0, publication-only) vs landmark-updated (L=7,30).

Converts F6's negative result into a defensible operational recommendation: how much
PR-AUC / recall you buy by WAITING L days after disclosure (to let the EPSS trajectory
form) vs the lead-time you give up. GPU xgb-AFT, in-wild labels (VulnCheck from data/live).
L=0 is the deployable cold-start head (publication-only features, no EPSS trajectory);
L=7,30 add the EPSS landmark trajectory and restart the clock to the landmark.

Note: the cohorts differ by design -- L>0 drops events within L days of publication
(restart_clock), so n_test_events shrinks with L. That trade-off IS the message.
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, rolling_origin_backtest
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.landmark import build_epss_features
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
ARTIFACT_DIR = "artifacts/bt_epss"
EPSS_PATH = "epss_history-001.parquet"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
LANDMARKS, MODEL = (7, 30), "xgb"

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
print(f"in-wild sources={sorted(event_frames)}", flush=True)

features_pub = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
print(f"building EPSS landmark trajectory for L={LANDMARKS} (one fused scan) ...", flush=True)
epss = build_epss_features(corpus, EPSS_PATH, landmarks=LANDMARKS, snapshot_date=SNAPSHOT)
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))


def _aggregate_for(landmark):
    if landmark == 0:  # instant head: publication-only features, no landmark clock
        feats, kw = features_pub, {"feature_view": "publication_only"}
    else:  # landmark-updated: add the EPSS trajectory + restart the clock to L
        feats, kw = features_pub.merge(epss[landmark], on="cve_id", how="left"), {"landmark_days": landmark}
    res = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL,
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start, **kw,
    )
    return res["aggregate"]


out = {}
for landmark in (0, *LANDMARKS):
    agg = _aggregate_for(landmark)
    row = {
        "pr_auc": {h: agg["horizon_pr_auc"].get(str(h), {}).get("mean") for h in (7, 30, 90)},
        "recall_at_top_30": agg["recall_at_top"].get("30", {}).get("mean"),
        "lead_time_days_median": agg.get("lead_time_days_median"),
        "n_test_events": agg.get("test_events_total"),
        "n_origins": agg.get("n_origins"),
    }
    out[f"L={landmark}"] = row
    print(
        f"  L={landmark}: PR-AUC@7={row['pr_auc'][7]} @30={row['pr_auc'][30]} @90={row['pr_auc'][90]} "
        f"| recall@30={row['recall_at_top_30']} | lead_time={row['lead_time_days_median']} "
        f"| events={row['n_test_events']}",
        flush=True,
    )

Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/operating_points.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/operating_points.json", flush=True)
