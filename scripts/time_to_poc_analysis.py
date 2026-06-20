"""Direction 1 (RQ1) — time-to-first-PoC on the clean recent cohort (published>=2021,
PoC-date bulk-index artifact controlled; see pipeline_characterization_2026-06.md).
Which publication-time features predict days-to-PoC, and how do Cox vs XGBoost-AFT
compare? Held-out time split, feature importance, clean-vs-all-cohort contrast.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import _fit
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import (
    _risk_scores,
    evaluate_survival,
    prepare_modeling_frame,
    survival_at,
    time_split_frame,
)

OUT = Path("data/merged")
SNAP, MIN_PUB, HZ = "2026-03-14", "2021-01-01", (7, 30, 90, 180)

corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
feats = pd.read_parquet("artifacts/merged/publication_features.parquet")
name, col = EVENT_SOURCES["poc"]  # ('poc_dates', 'poc_first_seen')
poc = load_optional_event(OUT, name, col)  # NB: NOT unique per cve (19k CVEs have >1 PoC-source row)
# dedup to the EARLIEST PoC per CVE (= first weaponization); else the merge explodes
# and double-counts CVEs with multiple PoC sources (caught by the dup-cve_id RE check).
poc = poc.sort_values(col).drop_duplicates("cve_id", keep="first")[["cve_id", col]]

# single-source time-to-PoC labels: clock origin = published, event = first PoC
m = corpus.merge(poc, on="cve_id", how="left")
pub = pd.to_datetime(m["published"], utc=True)
poc_d = pd.to_datetime(m[col], utc=True)
snap = pd.Timestamp(SNAP, tz="UTC")
m["event_observed"] = (poc_d.notna() & (poc_d <= snap)).to_numpy()
m["duration_days"] = np.where(m["event_observed"], (poc_d - pub).dt.days, (snap - pub).dt.days)
m["negative_duration_flag"] = (m["event_observed"] & ((poc_d - pub).dt.days < 0)).to_numpy()
labels = m[["cve_id", "published", "duration_days", "event_observed", "negative_duration_flag"]]


def run(restrict_recent, tag):
    frame = prepare_modeling_frame(labels, feats)
    if restrict_recent:
        p = pd.to_datetime(frame["published"], utc=True)
        frame = frame[p >= pd.Timestamp(MIN_PUB, tz="UTC")].reset_index(drop=True)
    cut = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
    tr, te = time_split_frame(frame, str(cut.date()))
    out = {"tag": tag, "n": len(frame), "n_events": int(frame["event_observed"].sum()),
           "median_ttp_days": float(frame.loc[frame["event_observed"].astype(bool), "duration_days"].median()),
           "n_test_events": int(te["event_observed"].sum())}
    for kind in ("cox", "xgb"):
        model = _fit(kind, tr)
        x = te[list(model.feature_cols_)].astype(float)
        ev = evaluate_survival(model, tr, te, horizons=HZ, kind=kind,
                               surv_at_horizons=survival_at(model, x, list(HZ), kind),
                               risk=_risk_scores(model, x, kind))
        out[f"{kind}_cindex"] = ev["c_index_ipcw"]
        out[f"{kind}_cindex_ci"] = ev["c_index_ci95"]
        out[f"{kind}_auc"] = ev.get("horizon_auc")
    cox = _fit("cox", tr)  # feature importance from cox |coef|
    out["top_cox_coef"] = cox.params_.abs().sort_values(ascending=False).head(15).round(4).to_dict()
    print(f"[{tag}] n={out['n']} ev={out['n_events']} test_ev={out['n_test_events']} "
          f"median_ttp={out['median_ttp_days']:.0f}d cox={out['cox_cindex']:.3f} xgb={out['xgb_cindex']:.3f}",
          flush=True)
    return out


results = {"clean_recent": run(True, "published>=2021"),
           "all_cohort": run(False, "all (artifact-affected)")}
Path("artifacts/merged/time_to_poc.json").write_text(json.dumps(results, indent=2, default=str))
print("\ntop cox |coef| (clean cohort):", list(results["clean_recent"]["top_cox_coef"])[:8], flush=True)
print("wrote artifacts/merged/time_to_poc.json", flush=True)
