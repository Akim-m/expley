"""A3: (1) seed-variance of the structural in-wild headline; (2) bounded random
hyperparameter search with an honest tune/confirm origin split.

Search protocol (anti-backtest-overfitting): 16 sampled configs are scored on
the FIRST 8 origins only (tune set); the single winner is then compared to the
default config on the LAST 7 origins (confirm set) with paired deltas. Adopt
only if the confirm-set delta's CI does not sit below 0.
Writes artifacts/a3_seed_and_tune.json.
"""
import itertools
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
SNAPSHOT, START = "2026-03-14", "2022-01-01"
N_CONFIGS, SEEDS = 16, (0, 1, 2, 3, 4)

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
tune_origins, confirm_origins = origins[:8], origins[8:]
clock_start = in_wild_clock_start(tuple(event_frames))


def run(origin_list, model_kwargs=None):
    return rolling_origin_backtest(
        corpus, event_frames, features, snapshot_date=SNAPSHOT, origins=origin_list,
        model="xgb", label_set="in_wild", horizons=(30, 90), clock_start=clock_start,
        model_kwargs=model_kwargs,
    )


def auc30(res):
    v = res["aggregate"].get("horizon_auc", {}).get("30", {})
    return v.get("mean")


# ---- Part 1: seed variance on the FULL origin set --------------------------
print("Part 1: seed variance ...", flush=True)
seed_aucs = {}
for s in SEEDS:
    t0 = time.perf_counter()
    r = run(origins, {"seed": s})
    seed_aucs[s] = {"auc30": auc30(r),
                    "auc90": r["aggregate"]["horizon_auc"]["90"]["mean"]}
    print(f"  seed {s}: AUC@30 {seed_aucs[s]['auc30']:.4f} "
          f"({time.perf_counter()-t0:.0f}s)", flush=True)
vals30 = [v["auc30"] for v in seed_aucs.values()]
vals90 = [v["auc90"] for v in seed_aucs.values()]
seed_summary = {
    "auc30": {"mean": float(np.mean(vals30)), "sd": float(np.std(vals30)),
              "min": min(vals30), "max": max(vals30)},
    "auc90": {"mean": float(np.mean(vals90)), "sd": float(np.std(vals90)),
              "min": min(vals90), "max": max(vals90)},
}
print("seed spread:", json.dumps(seed_summary), flush=True)

# ---- Part 2: bounded random search (tune on first 8, confirm on last 7) ----
print("Part 2: bounded search ...", flush=True)
GRID = list(itertools.product((0.03, 0.05, 0.1), (4, 6, 8), (300, 500, 800),
                              (0.5, 1.0, 2.0)))
rng = np.random.default_rng(0)
sampled = [GRID[i] for i in rng.choice(len(GRID), size=N_CONFIGS, replace=False)]
DEFAULT = {"learning_rate": 0.05, "max_depth": 6, "num_rounds": 500, "sigma": 1.0}
trials = []
for lr, depth, rounds, sigma in sampled:
    kw = {"learning_rate": lr, "max_depth": depth, "num_rounds": rounds, "sigma": sigma}
    t0 = time.perf_counter()
    r = run(tune_origins, kw)
    trials.append({"config": kw, "tune_auc30": auc30(r),
                   "wall_s": round(time.perf_counter() - t0, 1)})
    print(f"  {kw} -> tune AUC@30 {trials[-1]['tune_auc30']}", flush=True)

best = max(trials, key=lambda t: (t["tune_auc30"] is not None, t["tune_auc30"]))
print("tune winner:", json.dumps(best), flush=True)

confirm_best = run(confirm_origins, best["config"])
confirm_default = run(confirm_origins, DEFAULT)
confirm_delta = {
    str(h): paired_origin_deltas(confirm_best, confirm_default, "horizon_auc", h)
    for h in (30, 90)
}
out = {
    "protocol": "16 configs tuned on origins[:8]; winner vs default confirmed on origins[8:]",
    "seed_variance": {"per_seed": seed_aucs, "summary": seed_summary},
    "search_trials": trials,
    "tune_winner": best,
    "default_config": DEFAULT,
    "confirm_deltas_winner_minus_default": confirm_delta,
    "confirm_aggregates": {"winner": confirm_best["aggregate"]["horizon_auc"],
                           "default": confirm_default["aggregate"]["horizon_auc"]},
}
Path("artifacts/a3_seed_and_tune.json").write_text(json.dumps(out, indent=1))
for h in (30, 90):
    d = confirm_delta[str(h)]
    print(f"CONFIRM AUC@{h}: Δ{d['mean_delta']:+.4f} ci={d['ci95']} win={d['win_frac']:.2f}")
