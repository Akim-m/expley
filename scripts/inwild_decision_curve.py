"""Is the in-wild ranker operationally useful, or does a good AUC hide ~zero net benefit?

Decision-curve / net-benefit analysis (temporal_exploit.decision_curve) on a single
recent in-wild split. At a <1% base rate, a 0.82-AUC ranker can still beat the trivial
"treat-all"/"treat-none" policies only over a narrow band of decision thresholds — this
quantifies that band honestly. Uses the +VulnCheck in-wild set, no clock floor (the
config the floor ablation showed is better), cox, EPSS features.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.decision_curve import net_benefit_table
from temporal_exploit.labels import IN_WILD_SOURCES, build_in_wild_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import fit_cox, prepare_modeling_frame, survival_at, time_split_frame

OUT = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAP, CUTOFF, H = "2026-03-14", "2024-06-01", 90

corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
ef = {}
for s in IN_WILD_SOURCES:
    if s == "vulncheck_kev":
        ef[s] = (pd.read_parquet("data/live/vulncheck_kev.parquet"), "vulncheck_kev_date_added"); continue
    if s in EVENT_SOURCES:
        pq, dc = EVENT_SOURCES[s]
        fr = load_optional_event(OUT, pq, dc)
        if fr is not None:
            ef[s] = (fr, dc)

labels = build_in_wild_labels(corpus, ef, SNAP)
frame = prepare_modeling_frame(labels, features)
train, test = time_split_frame(frame, CUTOFF)
cox = fit_cox(train)
X_test = test[list(cox.feature_cols_)].astype(float)
risk = 1.0 - survival_at(cox, X_test, [H], "cox")[:, 0]  # predicted P(event by H)
dur = test["duration_days"].to_numpy(float)
evt = test["event_observed"].to_numpy(bool)
base = float((evt & (dur <= H)).mean())

thr = [0.001, 0.002, 0.005, 0.01, 0.02, 0.03, 0.05, 0.1]
tbl = net_benefit_table(risk, dur, evt, H, thr)
tbl["beats_all_and_none"] = tbl["net_benefit_model"] > tbl[["net_benefit_all", "net_benefit_none"]].max(axis=1)

print(f"n_train={len(train)} n_test={len(test)}  event-by-{H}d base rate={base:.4f}", flush=True)
print(tbl.to_string(index=False), flush=True)
useful = tbl.loc[tbl["beats_all_and_none"], "threshold"].tolist()
print(f"\nmodel beats treat-all AND treat-none at thresholds: {useful}", flush=True)
Path("artifacts").mkdir(exist_ok=True)
json.dump({"base_rate": base, "n_test": int(len(test)), "horizon": H,
           "table": tbl.to_dict(orient="records"), "useful_thresholds": useful},
          open("artifacts/inwild_decision_curve.json", "w"), indent=2)
print("wrote artifacts/inwild_decision_curve.json", flush=True)
