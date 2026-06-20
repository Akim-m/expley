"""Era-stress harness: quantify NON-STATIONARITY (the validity gate).

The median time-to-weaponization has collapsed (~745d for old CVEs -> ~44d recently) as
PoC tooling and mass-scanning matured. A model trained on the slow era may rank the fast
era poorly -- and every backtest number that mixes eras is suspect until we measure this.
era_stress_eval trains on the pre-train_max era and tests on the post-test_min era, against
an IN-PERIOD control (train+test both early) so the reported degradation is the ERA SHIFT,
not the inherent difficulty of the recent cohort.

Runs on first_weaponization (190k events, powered). GPU xgb-AFT.
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import era_stress_eval
from temporal_exploit.cli import EVENT_FEATURE_COLUMNS, EVENT_SOURCES, load_optional_event
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT = "2026-03-14"
MODEL = "xgb"
# (label, train_max, in_period_split, test_min) -- escalating era gaps
ERAS = [
    ("2022_vs_2024", "2022-12-31", "2021-12-31", "2024-06-01"),
    ("2023_vs_2025", "2023-12-31", "2022-12-31", "2025-01-01"),
]


def _fmt(v):
    return f"{v:.4f}" if isinstance(v, float) else str(v)


corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    extra = EVENT_FEATURE_COLUMNS.get(source, ())
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col, extra)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col, extra)
    if frame is not None:
        event_frames[source] = (frame, date_col)
print(f"sources loaded={sorted(event_frames)}", flush=True)

features = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")

results = {}
for label, train_max, split, test_min in ERAS:
    res = era_stress_eval(
        corpus, event_frames, features, SNAPSHOT,
        train_max=train_max, test_min=test_min, in_period_split=split,
        model=MODEL, label_set="first_weaponization", metric_horizon=90,
        feature_view="publication_only",
    )
    results[label] = res
    print(
        f"[{label}] cross-era AUC={_fmt(res['cross_era_auc'])} "
        f"in-period AUC={_fmt(res['in_period_auc'])} "
        f"degradation={_fmt(res['degradation_delta'])} "
        f"n_test_events={res['n_cross_test_events']}",
        flush=True,
    )

Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/era_stress.json", "w") as fh:
    json.dump(results, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/era_stress.json", flush=True)
