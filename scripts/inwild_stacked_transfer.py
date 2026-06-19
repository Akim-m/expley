"""Stacked transfer: inject the abundant first-weaponization signal into the
rare in-wild model as a single covariate.

The research's #1 *model* pathway (transfer / borrow-strength): the ~100k+
first-weaponization events estimate a robust feature->weaponization-propensity
map that the ~396-event in-wild model can't learn alone. At each rolling origin
T we fit a first-weaponization Cox on data knowable at T, score every CVE's
publication-time features with it, and feed that `source_risk` as one extra
covariate to the in-wild Cox. Leakage-safe: the source model is point-in-time
(published < T) and `source_risk` is a publication-time-knowable transform of
features the target already uses. Compares baseline vs stacked on identical
origins.
"""
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import make_origins, rolling_origin_backtest
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.labels import build_first_weaponization_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import fit_cox, prepare_modeling_frame

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
SRC_CAP = 40000  # cap source-train rows: fit_cox on 300k is slow, signal saturates

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(s for s in event_frames if s in IN_WILD_SOURCES))

# precompute the all-CVE feature matrix once (publication-time features, no labels)
feat_cols_all = [c for c in features.columns if c not in ("cve_id", "published")]
X_all = features.set_index("cve_id")[feat_cols_all].astype(float)


def stack_source(t: pd.Timestamp) -> pd.DataFrame:
    """First-weaponization Cox fit on published<t -> log-partial-hazard for every CVE."""
    src = build_first_weaponization_labels(corpus, event_frames, t.strftime("%Y-%m-%d"))
    src_pub = pd.to_datetime(src["published"], utc=True)
    src_frame = prepare_modeling_frame(src[src_pub < t], features)
    if len(src_frame) > SRC_CAP:
        src_frame = src_frame.sample(n=SRC_CAP, random_state=0).reset_index(drop=True)
    model = fit_cox(src_frame)
    risk = model.predict_partial_hazard(X_all[model.feature_cols_])
    return pd.DataFrame({"cve_id": X_all.index, "source_risk": np.log(np.asarray(risk))})


def run(tag, augment_fn):
    res = rolling_origin_backtest(
        corpus, event_frames, features, SNAPSHOT, origins, model="cox",
        label_set="in_wild", horizons=HORIZONS, clock_start=clock_start,
        augment_fn=augment_fn,
    )
    agg = res["aggregate"]
    print(f"\n=== cox / {tag} — {agg['n_origins']} origins, {agg['test_events_total']} events ===")
    for h in (30, 90, 180):
        a = agg["horizon_auc"].get(str(h), {})
        rc = agg["recall_at_top"].get(str(h), {})
        ip = agg["ipa"].get(str(h), {})
        if a:
            print(f"  h={h:>3}: AUC {a.get('mean'):.4f}±{a.get('sd'):.3f} (med {a.get('median'):.4f})  "
                  f"recall {rc.get('mean'):.4f}  IPA {ip.get('mean'):+.5f}")
    print(f"  lead_time_days_median: {agg.get('lead_time_days_median')}")
    return agg


base = run("baseline (71 feat)", None)
stacked = run("stacked-transfer (+source_risk)", stack_source)
print("\nΔ AUC@90:", round(stacked["horizon_auc"]["90"]["mean"] - base["horizon_auc"]["90"]["mean"], 4),
      " Δ recall@90:", round(stacked["recall_at_top"]["90"]["mean"] - base["recall_at_top"]["90"]["mean"], 4),
      " Δ IPA@90:", round(stacked["ipa"]["90"]["mean"] - base["ipa"]["90"]["mean"], 5))
