"""EPSS circularity control: does the in-wild model beat an EPSS-only baseline?

EPSS is itself an in-wild predictor, so a T-inwild "win" must be attributable to
NON-EPSS signal, not EPSS distillation (see docs/ttw_research_plan_2026-06.md).
Runs three feature configs on identical origins -- full, no-EPSS, EPSS-only --
with the GPU xgb-AFT model (gpu-only-models), in-wild labels, and reports paired
per-origin deltas: full vs EPSS-only (must the model beat the baseline?) and full
vs no-EPSS (the marginal EPSS lift). Loads only in-wild sources (no 188k-row poc).
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import (
    make_origins,
    paired_origin_deltas,
    rolling_origin_backtest,
)
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
MODEL = "xgb"  # GPU AFT (gpu-only-models)

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:  # in-wild only: skip poc(188k)/tooling loads
        continue
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
epss_cols = epss_feature_columns(features_full.columns)
meta = [c for c in ("cve_id", "published") if c in features_full.columns]
configs = {
    "full": features_full,
    "no_epss": features_full.drop(columns=epss_cols),
    "epss_only": features_full[meta + epss_cols],
}

origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(s for s in event_frames if s in IN_WILD_SOURCES))
print(f"model={MODEL} epss_columns={epss_cols} origins={len(origins)}", flush=True)

res = {
    tag: rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL,
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    )
    for tag, feats in configs.items()
}

out = {
    "model": MODEL,
    "epss_columns": epss_cols,
    "per_model": {tag: r["aggregate"] for tag, r in res.items()},
    "full_vs_epss_only": {
        f"{m}_{h}": paired_origin_deltas(res["full"], res["epss_only"], m, h)
        for m in ("horizon_pr_auc", "horizon_auc") for h in (30, 90)
    },
    "full_vs_no_epss": {
        f"{m}_{h}": paired_origin_deltas(res["full"], res["no_epss"], m, h)
        for m in ("horizon_pr_auc", "horizon_auc") for h in (30, 90)
    },
}
for h in (30, 90):
    d = out["full_vs_epss_only"][f"horizon_pr_auc_{h}"]
    beats = d["ci95"] is not None and d["ci95"][0] > 0
    print(
        f"  full vs EPSS-only PR-AUC@{h}: delta {d['mean_delta']:+.4f} CI {d['ci95']} "
        f"n={d['n_paired']} -> {'beats EPSS-only' if beats else 'within error of EPSS-only'}",
        flush=True,
    )
Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/inwild_epss_ablation.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/inwild_epss_ablation.json", flush=True)
