"""Over-parameterization probe: full-71-feature cox vs a dense-signal-only cox.

The rare-event literature flags ~9.5 events-per-variable (664 in-wild events /
~70 features) as over-parameterized; the remedy is shrinkage + fewer features.
The 71 features are dominated by sparse one-hot blocks (20 CWE, ~10 ATT&CK-parent,
~22 CVSS-vector, 6 severity); this keeps only the ~12 dense high-signal features
and asks whether the sparse blocks earn their parameters *prospectively* or just
add variance. Same backtest, same origins — only the feature set changes.
"""
import sys
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
DENSE = [  # dense, non-sparse, domain-strong publication-time signals
    "cvss_v3_base", "cvss_v3_missing",
    "epss_at_publication", "epss_percentile_at_publication", "epss_at_publication_missing",
    "weakness_count", "vendor_count", "product_count",
    "attack_technique_count", "has_weakness", "has_attack_chain_mapping",
    "published_year",
]

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
features_full = pd.read_parquet(f"artifacts/bt_epss/publication_features.parquet")
keep = ["cve_id", "published"] + [c for c in DENSE if c in features_full.columns]
features_dense = features_full[keep]

origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(s for s in event_frames if s in IN_WILD_SOURCES))

for tag, feats in [("full-71", features_full), (f"dense-{len(keep) - 2}", features_dense)]:
    res = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model="cox",
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    )
    agg = res["aggregate"]
    print(f"\n=== cox / {tag} — {agg['n_origins']} origins, {agg['test_events_total']} events ===")
    for h in (30, 90):
        a = agg["horizon_auc"].get(str(h), {})
        rc = agg["recall_at_top"].get(str(h), {})
        ip = agg["ipa"].get(str(h), {})
        print(f"  h={h}: AUC {a.get('mean'):.4f}±{a.get('sd'):.3f} (med {a.get('median'):.4f})  "
              f"recall {rc.get('mean'):.4f}  IPA {ip.get('mean'):+.5f}")
    print(f"  lead_time_days_median: {agg.get('lead_time_days_median')}")
