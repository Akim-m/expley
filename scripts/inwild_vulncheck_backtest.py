"""Does the VulnCheck label expansion actually move the in-wild model?

Runs the rolling-origin backtest (cox) on the in-wild target with vs without the
fetched VulnCheck KEV labels (data/live/vulncheck_kev.parquet), on identical
origins/features. The expected win isn't a higher AUC (ranking was already good)
but more events -> lower variance and more stable short-horizon numbers.
"""
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.labels import IN_WILD_SOURCES
from temporal_exploit.loaders import load_parquet

OUT = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAP, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)

corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
origins = make_origins(SNAP, START, min_followup_days=180)


def frames(include_vc):
    ef = {}
    for s in IN_WILD_SOURCES:
        if s == "vulncheck_kev":
            if include_vc:
                ef[s] = (pd.read_parquet("data/live/vulncheck_kev.parquet"), "vulncheck_kev_date_added")
            continue
        if s in EVENT_SOURCES:
            pq, dc = EVENT_SOURCES[s]
            fr = load_optional_event(OUT, pq, dc)
            if fr is not None:
                ef[s] = (fr, dc)
    return ef


for tag, inc in [("baseline (KEV+0day)", False), ("+ VulnCheck KEV", True)]:
    ef = frames(inc)
    clock = in_wild_clock_start(tuple(ef))
    agg = rolling_origin_backtest(
        corpus, ef, features, SNAP, origins, model="cox", label_set="in_wild",
        horizons=HORIZONS, clock_start=clock,
    )["aggregate"]
    print(f"\n=== {tag} — {agg['n_origins']} origins, {agg['test_events_total']} test events ===", flush=True)
    for h in (30, 90, 180):
        a = agg["horizon_auc"].get(str(h), {})
        rc = agg["recall_at_top"].get(str(h), {})
        ip = agg["ipa"].get(str(h), {})
        if a:
            print(f"  h={h:>3}: AUC {a.get('mean'):.4f}±{a.get('sd'):.3f} (med {a.get('median'):.4f})  "
                  f"recall {rc.get('mean'):.4f}  IPA {ip.get('mean'):+.5f}", flush=True)
    print(f"  lead_time_days_median: {agg.get('lead_time_days_median')}", flush=True)
