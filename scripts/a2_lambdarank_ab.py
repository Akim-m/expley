"""A2 A/B: LambdaRank top-push (xgb_rank) vs XGB-AFT ranking on the in-wild
parity setup — identical origins, structural features only (NO EPSS data).
Adoption gate: significant paired wins on recall@top-K / coverage at small
efforts without giving up AUC. Writes artifacts/a2_lambdarank_ab.json."""
import json
import time
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.effort_metrics import recall_by_frac_deltas
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
SNAPSHOT, START = "2026-03-14", "2022-01-01"
EFFORT_GRID = (0.005, 0.01, 0.02, 0.05, 0.10)

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

features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
features = features.drop(columns=epss_feature_columns(features.columns))  # EPSS-free
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))
common = dict(snapshot_date=SNAPSHOT, origins=origins, label_set="in_wild",
              horizons=(7, 30, 90, 180), clock_start=clock_start, top_fracs=EFFORT_GRID)


def run(tag, model, model_kwargs=None):
    t0 = time.perf_counter()
    res = rolling_origin_backtest(corpus, event_frames, features, model=model,
                                  model_kwargs=model_kwargs, **common)
    print(tag, "wall_s:", round(time.perf_counter() - t0, 1), flush=True)
    return res


aft = run("aft", "xgb")
rank = run("rank", "xgb_rank", {"horizon": 30, "num_rounds": 300})

out = {
    "arms": "xgb_rank (rank:ndcg topk pairs, h=30 labels) vs xgb AFT — structural, no EPSS",
    "auc_deltas_rank_minus_aft": {
        str(h): paired_origin_deltas(rank, aft, "horizon_auc", h) for h in (30, 90)
    },
    "coverage_deltas_rank_minus_aft": {
        str(h): {f"{f:g}": recall_by_frac_deltas(rank, aft, f"{f:g}", h) for f in EFFORT_GRID}
        for h in (30, 90)
    },
    "aggregates": {"aft": aft["aggregate"], "rank": rank["aggregate"]},
}
Path("artifacts/a2_lambdarank_ab.json").write_text(json.dumps(out, indent=1))
for h in (30, 90):
    d = out["auc_deltas_rank_minus_aft"][str(h)]
    print(f"AUC@{h}: Δ{d['mean_delta']:+.4f} ci={d['ci95']} win={d['win_frac']:.2f}")
    for f in EFFORT_GRID:
        c = out["coverage_deltas_rank_minus_aft"][str(h)][f"{f:g}"]
        print(f"  cov@{f:.1%}: Δ{c['mean_delta']:+.3f} ci={c['ci95']} win={c['win_frac']:.2f}")
