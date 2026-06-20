"""In-wild rolling-origin head-to-head: GPU XGBoost-AFT vs a cox reference.

Per gpu-only-models, the model under test is GPU xgb-AFT; cox is retained ONLY as
the cox-relative reference for the paired_vs_cox delta (the stashed CPU survival
models rsf/gbm are not run by default). Loads the EXPANDED in-wild labels
(VulnCheck-KEV from data/live, 454->1368 events) and varies only the model on
identical origins, reporting paired per-origin deltas with PR-AUC (rare-event).
"""
import json
import sys
import time
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")  # VulnCheck-KEV (4969) + fresher in-wild sources live here, not out/
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT = "2026-03-14"
START = "2022-01-01"
HORIZONS = (7, 30, 90, 180)
MODELS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["xgb", "cox"]  # GPU xgb; cox=reference

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:  # in-wild head-to-head: skip poc (188k)/tooling loads
        continue
    # data/live first so VulnCheck-KEV is included (out/ predates it: 454 -> 1368 events)
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
missing = [s for s in IN_WILD_SOURCES if s not in event_frames]
print(f"in-wild sources loaded={sorted(event_frames)} missing={missing}", flush=True)

features = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))  # keys are already the in-wild sources
print(f"in_wild: {len(origins)} origins from {START}, clock_start={clock_start}, "
      f"features={features.shape[1] - 1}", flush=True)

results = {}
full = {}
for model in MODELS:
    t0 = time.time()
    res = rolling_origin_backtest(
        corpus, event_frames, features, SNAPSHOT, origins, model=model,
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    )
    agg = res["aggregate"]
    results[model] = agg
    full[model] = res
    dt = time.time() - t0
    auc = agg["horizon_auc"].get("90", {})
    pr = agg["horizon_pr_auc"].get("90", {})
    rec = agg["recall_at_top"].get("90", {})
    ipa = agg["ipa"].get("90", {})
    print(
        f"\n=== {model} ({dt:.0f}s) — {agg['n_origins']} origins, "
        f"{agg['test_events_total']} test events ===\n"
        f"  AUC@90:    mean {auc.get('mean')!r}  median {auc.get('median')!r}  sd {auc.get('sd')!r}\n"
        f"  PR-AUC@90: mean {pr.get('mean')!r}  median {pr.get('median')!r}\n"
        f"  recall@90: mean {rec.get('mean')!r}  median {rec.get('median')!r}\n"
        f"  IPA@90:    mean {ipa.get('mean')!r}  median {ipa.get('median')!r}\n"
        f"  lead_time_days_median: {agg.get('lead_time_days_median')!r}",
        flush=True,
    )

# Cross-model uncertainty: per-origin paired deltas vs cox on the SHARED origins.
# A challenger genuinely beats cox only if its 95% CI excludes 0 -- otherwise the gap
# is within the quarter-to-quarter noise. PR-AUC is the rare-event-informative metric.
paired_vs_cox = {}
if "cox" in full:
    for model in MODELS:
        if model == "cox":
            continue
        blocks = {
            f"{metric}_{h}": paired_origin_deltas(full[model], full["cox"], metric, h)
            for metric, h in (("horizon_auc", 90), ("horizon_pr_auc", 90), ("ipa", 90))
        }
        paired_vs_cox[model] = blocks
        for key in ("horizon_auc_90", "horizon_pr_auc_90"):
            d = blocks[key]
            verdict = "within error" if (d["ci95"] is None or d["ci95"][0] <= 0 <= d["ci95"][1]) \
                else ("beats cox" if d["mean_delta"] > 0 else "worse than cox")
            print(
                f"  paired {model}-cox {key}: delta {d['mean_delta']:+.4f} "
                f"CI {d['ci95']} (n={d['n_paired']}, win {d['win_frac']}) -> {verdict}",
                flush=True,
            )

output = {"baseline": "cox", "per_model": results, "paired_vs_cox": paired_vs_cox}
with open("artifacts/inwild_headtohead.json", "w") as fh:
    json.dump(output, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/inwild_headtohead.json", flush=True)
