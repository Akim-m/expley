"""MERGED-BUILD re-evaluation (data/merged + artifacts/merged): does the in-wild
model beat an EPSS-only baseline on the VulnCheck/NVD++-expanded labels?

Same design as inwild_epss_ablation.py but pointed at the merged build produced by
the 2026-06-20 data-expansion (merge -> build-dataset). Re-aims the PR-AUC-vs-EPSS-only
bar at the expanded in-wild labels (~4.7k events vs ~454 handover).

EPSS circularity control: does the in-wild model beat an EPSS-only baseline?

EPSS is itself an in-wild predictor, so a T-inwild "win" must be attributable to
NON-EPSS signal, not EPSS distillation (see docs/ttw_research_plan_2026-06.md).
Runs three feature configs on identical origins -- full, no-EPSS, EPSS-only --
with the GPU xgb-AFT model (gpu-only-models), in-wild labels, and reports paired
per-origin deltas: full vs EPSS-only (must the model beat the baseline?) and full
vs no-EPSS (the marginal EPSS lift). Loads only in-wild sources (no 188k-row poc).

NOTE: epss_only here is the STATIC publication-time EPSS (epss_at_publication*), the
FLOOR baseline -- NOT the landmark EPSS trajectory (velocity/max/rising), which the
rolling backtest does not load. So "full beats EPSS-only" is necessary-but-not-
sufficient evidence against trajectory-EPSS distillation; the strong control needs
landmark + restart_clock plumbing in rolling_origin_backtest (tracked separately).
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

OUT_DIR = Path("data/merged")  # NVD++-expanded corpus (359k)
LIVE_DIR = Path("data/merged")  # merged in-wild sources (VulnCheck KEV folded in)
ARTIFACT_DIR = "artifacts/merged"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
MODEL = "xgb"  # GPU AFT (gpu-only-models)

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:  # in-wild only: skip poc(188k)/tooling loads
        continue
    # in-wild sources from data/live so VulnCheck-KEV is included (the handover
    # out/ predates it: 454 -> 1368 eligible events); fall back to handover.
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)

missing = [s for s in IN_WILD_SOURCES if s not in event_frames]
print(f"in-wild sources loaded={sorted(event_frames)} missing={missing}", flush=True)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
epss_cols = epss_feature_columns(features_full.columns)
# the EPSS-only baseline is the STATIC publication EPSS floor; assert no landmark
# trajectory column sneaks in (that would silently make it a much stronger baseline).
_STATIC_EPSS = {"epss_at_publication", "epss_percentile_at_publication", "epss_at_publication_missing"}
assert set(epss_cols) <= _STATIC_EPSS, (
    f"EPSS-only baseline expects only static publication EPSS; got {epss_cols}"
)
meta = [c for c in ("cve_id", "published") if c in features_full.columns]

origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))  # keys are already the in-wild sources
print(f"model={MODEL} static-EPSS-floor columns={epss_cols} origins={len(origins)}", flush=True)


def _features_for(tag):
    # built just-in-time so we never hold more than one derived ~198 MB copy at once
    if tag == "no_epss":
        return features_full.drop(columns=epss_cols)
    if tag == "epss_only":
        return features_full[meta + epss_cols]
    return features_full  # "full" reuses the base frame -- no copy


res = {}
for tag in ("full", "no_epss", "epss_only"):
    feats = _features_for(tag)
    res[tag] = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL,
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    )
    if feats is not features_full:
        del feats  # free the derived copy before building the next config

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
with open("artifacts/merged/inwild_epss_ablation.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True)
print("\nwrote artifacts/merged/inwild_epss_ablation.json", flush=True)
