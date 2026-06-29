"""EPSS-parity head-to-head: our in-wild model vs EPSS on the in-wild target.

Target = in-wild exploitation (KEV / Google 0-day / VulnCheck) -- the closest honest
proxy for what EPSS predicts. NOTE (adversarial RE 2026-06-30): in practice the kept
test events are ~93% VulnCheck-KEV catalog membership (CISA adds ~90, Google 0-day 0 --
all dropped as pre-publication negative-duration), and the event date is an administrative
catalog-add date (median lag ~175d), not exploitation onset. So this is a publication-
anchored known-exploited proxy; the head-to-head is fair (both arms see the identical
proxy) but "same target as EPSS" is the soft part, not the number.
On identical walk-forward origins, reports for two arms:
  - epss_only  : the EPSS-at-publication baseline (what EPSS alone gives you)
  - structural : our publication-time structural model with NO EPSS (deployable config)
Metrics: ranking AUC@30/90, PR-AUC@30, and EPSS's deployment metric recall@top-1/5/10%@30.
Prints an honest verdict (where EPSS wins, where we win) with paired CIs on AUC/PR-AUC.
"""
import json
import os
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")  # VulnCheck-expanded in-wild events
ARTIFACT_DIR = "artifacts/bt_epss"
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
KS = (0.01, 0.05, 0.10)
MODEL = "xgb"

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:  # in-wild only; skip the 188k-row PoC frame
        continue
    frame = load_optional_event(LIVE_DIR, parquet_name, date_col)
    if frame is None:
        frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
# optional in-wild label subset for the VulnCheck label-lift comparison
# (e.g. INWILD_SUBSET=kev = CISA-only; default = all in-wild sources)
_subset = os.environ.get("INWILD_SUBSET")
_tag = ("_" + _subset.replace(",", "-")) if _subset else ""
if _subset:
    _keep = {s.strip() for s in _subset.split(",")}
    event_frames = {k: v for k, v in event_frames.items() if k in _keep}
print(f"in-wild sources loaded={sorted(event_frames)} (subset={_subset or 'all'})", flush=True)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
epss_cols = epss_feature_columns(features_full.columns)
# the EPSS arm must be the STATIC publication-EPSS floor, not a landmark trajectory
# (that would silently make it a much stronger baseline). Mirror the ablation's guard.
_STATIC_EPSS = {"epss_at_publication", "epss_percentile_at_publication", "epss_at_publication_missing"}
assert set(epss_cols) <= _STATIC_EPSS, f"EPSS-only baseline expects only static EPSS; got {epss_cols}"
meta = [c for c in ("cve_id", "published") if c in features_full.columns]
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))
print(f"model={MODEL} epss_cols={epss_cols} origins={len(origins)}", flush=True)

res = {}
# our publication-time structural model, NO EPSS (the deployable in-wild config)
res["structural"] = rolling_origin_backtest(
    corpus, event_frames, features_full.drop(columns=epss_cols), SNAPSHOT, origins,
    model=MODEL, label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
)
# CORRECT EPSS baseline: rank by the raw EPSS percentile DIRECTLY (a calibrated
# score is used as-is, not re-fit through a survival model -> score_col passthrough).
res["epss_score"] = rolling_origin_backtest(
    corpus, event_frames, features_full, SNAPSHOT, origins, model=MODEL,
    label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
    score_col="epss_percentile_at_publication",
)
# CONTRAST: the naive xgb-AFT-on-EPSS arm (what the old ablation did) -- it collapses
# to ~chance on this rare/censored target; kept to document the artifact, not as a baseline.
res["epss_xgb_naive"] = rolling_origin_backtest(
    corpus, event_frames, features_full[meta + epss_cols], SNAPSHOT, origins, model=MODEL,
    label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
)


def _recall_table(agg):
    rb = agg.get("recall_at_top_by_frac", {})
    return {f"{k:g}": rb.get(f"{k:g}", {}).get("30", {}).get("mean") for k in KS}


def _auc(agg, metric, h):
    return agg.get(metric, {}).get(str(h), {}).get("mean")


out = {
    "target": ("in_wild (KEV / Google 0-day / VulnCheck) -- publication-anchored known-exploited "
               "proxy for what EPSS predicts; kept test events ~93% VulnCheck, catalog-add timing "
               "(median lag ~175d) not exploitation onset"),
    "model": MODEL, "epss_columns": epss_cols, "n_origins": len(origins),
    "epss_arm": ("epss_score = raw epss_percentile_at_publication used directly as risk "
                 "(score_col passthrough); epss_xgb_naive = collapsed model-on-EPSS contrast"),
    "per_arm": {
        tag: {
            "auc_30": _auc(r["aggregate"], "horizon_auc", 30),
            "auc_90": _auc(r["aggregate"], "horizon_auc", 90),
            "pr_auc_30": _auc(r["aggregate"], "horizon_pr_auc", 30),
            "recall_at_top_30": _recall_table(r["aggregate"]),
            "test_events_total": r["aggregate"]["test_events_total"],
        }
        for tag, r in res.items()
    },
    "structural_vs_epss_score": {
        f"{m}_{h}": paired_origin_deltas(res["structural"], res["epss_score"], m, h)
        for m in ("horizon_auc", "horizon_pr_auc") for h in (30, 90)
    },
}
Path("artifacts").mkdir(exist_ok=True)
with open(f"artifacts/inwild_epss_parity{_tag}.json", "w") as fh:
    json.dump(out, fh, indent=2, sort_keys=True, default=str)

s = out["per_arm"]["structural"]
e = out["per_arm"]["epss_score"]
nv = out["per_arm"]["epss_xgb_naive"]
d = out["structural_vs_epss_score"]["horizon_auc_30"]
print(f"\n=== EPSS parity (same in-wild target, {len(origins)} origins, {s['test_events_total']} test events) ===")
print(f"AUC@30   structural {s['auc_30']:.3f}  vs EPSS-score {e['auc_30']:.3f}  "
      f"(naive xgb-on-EPSS {nv['auc_30']:.3f})   paired delta {d['mean_delta']:+.3f} CI {d['ci95']}")
for k in KS:
    kk = f"{k:g}"
    sv, ev = s["recall_at_top_30"][kk], e["recall_at_top_30"][kk]
    winner = "structural" if (sv or 0) > (ev or 0) else "EPSS"
    print(f"recall@top-{k:.0%}@30   structural {sv}  vs EPSS-score {ev}   -> {winner} wins")
print(f"wrote artifacts/inwild_epss_parity{_tag}.json")
