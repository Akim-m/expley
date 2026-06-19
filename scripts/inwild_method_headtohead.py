"""In-wild rolling-origin head-to-head: cox vs RSF vs gradient-boosted survival.

The user's instruction — "don't fixate on one method, keep checking for a better
one." The single-split work compared only cox/xgb/cure; this adds the two
non-linear ensemble classes the literature flags as the real challengers to a
penalized Cox on tabular survival, and lets the *prospective* backtest decide.
Loads corpus/events/features once; varies only the model on identical origins.
"""
import json
import sys
import time
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, rolling_origin_backtest
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT = "2026-03-14"
START = "2022-01-01"
HORIZONS = (7, 30, 90, 180)
MODELS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["cox", "rsf", "gbm"]

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
features = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
active = tuple(s for s in event_frames if s in IN_WILD_SOURCES)
clock_start = in_wild_clock_start(active)
print(f"in_wild: {len(origins)} origins from {START}, clock_start={clock_start}, "
      f"features={features.shape[1] - 1}", flush=True)

results = {}
for model in MODELS:
    t0 = time.time()
    res = rolling_origin_backtest(
        corpus, event_frames, features, SNAPSHOT, origins, model=model,
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    )
    agg = res["aggregate"]
    results[model] = agg
    dt = time.time() - t0

    def g(metric, h, stat="mean"):
        return agg.get(metric, {}).get(str(h), {}).get(stat) if metric != "recall_at_top" \
            else agg.get(metric, {}).get(str(h), {}).get(stat)

    auc = agg["horizon_auc"].get("90", {})
    rec = agg["recall_at_top"].get("90", {})
    ipa = agg["ipa"].get("90", {})
    print(
        f"\n=== {model} ({dt:.0f}s) — {agg['n_origins']} origins, "
        f"{agg['test_events_total']} test events ===\n"
        f"  AUC@90:    mean {auc.get('mean')!r}  median {auc.get('median')!r}  sd {auc.get('sd')!r}\n"
        f"  recall@90: mean {rec.get('mean')!r}  median {rec.get('median')!r}\n"
        f"  IPA@90:    mean {ipa.get('mean')!r}  median {ipa.get('median')!r}\n"
        f"  lead_time_days_median: {agg.get('lead_time_days_median')!r}",
        flush=True,
    )

with open("artifacts/inwild_headtohead.json", "w") as fh:
    json.dump(results, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/inwild_headtohead.json", flush=True)
