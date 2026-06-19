"""Temperature recalibration on the in-wild target: does the 1-param post-hoc
rescale improve the absolute-probability weak spot (IPA≈0) without touching the
ranking? Baseline cox vs cox+temperature on identical origins.
"""
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
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(s for s in event_frames if s in IN_WILD_SOURCES))


def run(tag, temperature):
    agg = rolling_origin_backtest(
        corpus, event_frames, features, SNAPSHOT, origins, model="cox",
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
        temperature=temperature,
    )["aggregate"]
    print(f"\n=== cox / {tag} ===")
    for h in (30, 90, 180):
        a = agg["horizon_auc"].get(str(h), {})
        ip = agg["ipa"].get(str(h), {})
        if a:
            print(f"  h={h:>3}: AUC {a.get('mean'):.4f}  IPA mean {ip.get('mean'):+.5f}  "
                  f"median {ip.get('median'):+.5f}")
    return agg


base = run("baseline", False)
temp = run("temperature", True)
print("\nΔ IPA mean (temp − base):", {
    h: round(temp["ipa"].get(str(h), {}).get("mean", 0) - base["ipa"].get(str(h), {}).get("mean", 0), 5)
    for h in (30, 90, 180)
})
print("AUC@90 base vs temp (should be identical):",
      round(base["horizon_auc"]["90"]["mean"], 4), round(temp["horizon_auc"]["90"]["mean"], 4))
