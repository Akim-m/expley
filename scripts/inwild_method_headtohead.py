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

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
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
    if source not in IN_WILD_SOURCES:  # in-wild head-to-head: skip poc (188k)/tooling loads
        continue
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

# Cross-model uncertainty: per-origin paired deltas vs cox on the SHARED origins.
# A challenger only genuinely beats cox if its 95% CI excludes 0 -- otherwise the
# gap (e.g. a 0.005 AUC/c-index lead) is within the quarter-to-quarter noise. This
# is what the per-model `sd` alone could not tell you: it is the paired test.
paired_vs_cox = {}
if "cox" in full:
    for model in MODELS:
        if model == "cox":
            continue
        blocks = {
            f"{metric}_{h}": paired_origin_deltas(full[model], full["cox"], metric, h)
            for metric, h in (("horizon_auc", 90), ("ipa", 90))
        }
        paired_vs_cox[model] = blocks
        a90 = blocks["horizon_auc_90"]
        verdict = "within error" if (a90["ci95"] is None or a90["ci95"][0] <= 0 <= a90["ci95"][1]) \
            else ("beats cox" if a90["mean_delta"] > 0 else "worse than cox")
        print(
            f"  paired {model}-cox AUC@90: delta {a90['mean_delta']:+.4f} "
            f"CI {a90['ci95']} (n={a90['n_paired']}, win {a90['win_frac']}) -> {verdict}",
            flush=True,
        )

output = {"baseline": "cox", "per_model": results, "paired_vs_cox": paired_vs_cox}
with open("artifacts/inwild_headtohead.json", "w") as fh:
    json.dump(output, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/inwild_headtohead.json", flush=True)
