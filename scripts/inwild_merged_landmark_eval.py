"""MERGED-BUILD landmark EPSS-trajectory circularity control (the STRONG bar).

The static-EPSS ablation (scripts/inwild_merged_eval.py) showed the in-wild model
beats a *static* publication-EPSS baseline (~0.50 AUC) on the expanded labels. That
is the WEAK bar. This script runs the STRONG bar: does the model still beat an
EPSS-only baseline once that baseline is upgraded to the full landmark TRAJECTORY
(velocity / max / mean / std / rising, offline AUC ~0.63-0.68)?

Regime: L=30 landmark. rolling_origin_backtest(landmark_days=30) applies
landmark.restart_clock per origin -- it drops every CVE whose event/censor time is
<= published+30d (the ~2k fast in-wild events are conditioned out; ~2,693 remain)
and shifts the clock to start at the landmark, so the as-of-L trajectory features
are leakage-safe. full / no_epss / epss_only on identical origins + identical
restart_clock cohort; only the feature set differs. GPU xgb-AFT, in-wild labels.

Efficiency: reuse the precomputed artifacts/merged/landmark_features_30d.parquet
(written by build-dataset via the same landmark.py) instead of re-running the
375M-row build_epss_features scan -- byte-identical EPSS-trajectory columns, no
extra memory-heavy pass. Merges only the 11 _LANDMARK_EPSS_COLUMNS (the EPSS
trajectory), NOT the landmark tooling columns, to stay comparable to the handover
F6 ablation (scripts/inwild_epss_ablation_landmark.py).
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
from temporal_exploit.landmark import _LANDMARK_EPSS_COLUMNS
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("data/merged")  # NVD++-expanded corpus (359k)
LIVE_DIR = Path("data/merged")  # merged in-wild sources (VulnCheck KEV folded in)
ARTIFACT_DIR = "artifacts/merged"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
LANDMARK, MODEL = 30, "xgb"

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
missing = [s for s in IN_WILD_SOURCES if s not in event_frames]
print(f"in-wild sources loaded={sorted(event_frames)} missing={missing}", flush=True)

# publication features + the PRECOMPUTED landmark EPSS trajectory (no 375M rescan)
features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
lm = pd.read_parquet(f"{ARTIFACT_DIR}/landmark_features_{LANDMARK}d.parquet")
lm_epss = lm[["cve_id", *_LANDMARK_EPSS_COLUMNS]]  # trajectory only, not landmark tooling
features_full = features_full.merge(lm_epss, on="cve_id", how="left")
assert features_full[_LANDMARK_EPSS_COLUMNS].isna().sum().sum() == 0, "NaN after landmark merge"
del lm, lm_epss
epss_cols = epss_feature_columns(features_full.columns)  # static publication + landmark trajectory
# days_to_epss_* are EPSS-DERIVED (days to EPSS crossing 0.1/0.5) but escape the
# "epss" prefix filter -- fold them in so no_epss is TRULY EPSS-free and epss_only
# is the COMPLETE EPSS baseline (else 2 EPSS-timing features leak into structural).
epss_cols = epss_cols + [c for c in ("days_to_epss_01", "days_to_epss_05") if c in features_full.columns]
meta = [c for c in ("cve_id", "published") if c in features_full.columns]
print(f"model={MODEL} landmark={LANDMARK} EPSS columns (incl. trajectory)={epss_cols}", flush=True)

origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))
print(f"origins={len(origins)} clock_start={clock_start}", flush=True)


def _features_for(tag):
    if tag == "no_epss":
        return features_full.drop(columns=epss_cols)
    if tag == "epss_only":
        return features_full[meta + epss_cols]
    return features_full


res = {}
for tag in ("full", "no_epss", "epss_only"):
    feats = _features_for(tag)
    res[tag] = rolling_origin_backtest(
        corpus, event_frames, feats, SNAPSHOT, origins, model=MODEL, label_set="in_wild",
        horizons=HORIZONS, clock_start=clock_start, landmark_days=LANDMARK,
    )
    if feats is not features_full:
        del feats

out = {
    "model": MODEL,
    "landmark_days": LANDMARK,
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
for tag in ("full", "no_epss", "epss_only"):
    agg = out["per_model"][tag]
    au = agg.get("horizon_auc", {})
    pr = agg.get("horizon_pr_auc", {})
    print(f"  [{tag:9s}] AUC@30={au.get('30',{}).get('mean'):.3f} AUC@90={au.get('90',{}).get('mean'):.3f} "
          f"PR-AUC@30={pr.get('30',{}).get('mean'):.4f} PR-AUC@90={pr.get('90',{}).get('mean'):.4f}", flush=True)
# The bar must be read on BOTH metrics: AUC (ranking) is well-resolved at this
# event rarity; PR-AUC (precision) is underpowered, so a PR-AUC tie is uninformative,
# NOT evidence of distillation. The structural no_epss-vs-epss_only gap is decisive.
def _verdict(delta):
    if delta["ci95"] is None:
        return "n/a"
    return "BEATS" if delta["ci95"][0] > 0 else ("within err" if delta["ci95"][1] > 0 else "LOSES")


for h in (30, 90):
    d = out["full_vs_epss_only"][f"horizon_pr_auc_{h}"]
    da = out["full_vs_epss_only"][f"horizon_auc_{h}"]
    print(
        f"  full vs complete-EPSS-only @{h}: "
        f"AUC delta {da['mean_delta']:+.4f} CI {[round(c,4) for c in da['ci95']] if da['ci95'] else None} -> {_verdict(da)} (ranking) | "
        f"PR-AUC delta {d['mean_delta']:+.4f} CI {[round(c,4) for c in d['ci95']] if d['ci95'] else None} -> {_verdict(d)} (precision, underpowered)",
        flush=True,
    )
# the decisive, leak-free statement: pure structural vs complete EPSS on ranking
sa, ea = (out["per_model"]["no_epss"]["horizon_auc"], out["per_model"]["epss_only"]["horizon_auc"])
for h in (30, 90):
    print(f"  STRUCTURAL-only AUC@{h}={sa[str(h)]['mean']:.3f} vs complete-EPSS-only AUC@{h}={ea[str(h)]['mean']:.3f} "
          f"(structural beats EPSS by {sa[str(h)]['mean'] - ea[str(h)]['mean']:+.3f})", flush=True)
Path(ARTIFACT_DIR).mkdir(parents=True, exist_ok=True)
with open(f"{ARTIFACT_DIR}/inwild_epss_ablation_landmark.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True, default=str)
print(f"\nwrote {ARTIFACT_DIR}/inwild_epss_ablation_landmark.json", flush=True)
