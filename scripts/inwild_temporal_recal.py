"""Does temporal recalibration recover in-wild calibration (IPA) without moving ranking?

Per rolling origin t: fit cox on train (published in [clock_start, t)); recalibrate the
Breslow baseline on the most-recent RECENT_DAYS of train (Booth 2020, temporal_recalibration);
score the next quarter's CVEs. Reports per-origin AUC@90 (must be ~identical -- rank-preserving)
and IPA@90 (base vs recalibrated). Also confirms the source-aware floor lifts by default
(in_wild_clock_start returns None with VulnCheck active).

HONEST EXPECTATION: temporal recalibration fixes a baseline that is stale relative to the
recent TRAIN regime; it cannot fix an origin where the TEST era is slower than anything in
train (e.g. 2022-04: 37 fast train events vs 98 slow test events -- unknowable at deployment).
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import make_origins
from temporal_exploit.cli import EVENT_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.labels import IN_WILD_SOURCES, build_in_wild_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import (
    _risk_scores, evaluate_survival, fit_cox, prepare_modeling_frame, survival_at,
)
from temporal_exploit.temporal_recalibration import temporal_recalibrate

OUT = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAP, START, HZ, RECENT_DAYS = "2026-03-14", "2022-01-01", (7, 30, 90, 180), 365

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

clock = in_wild_clock_start(tuple(ef))  # None now (VulnCheck active) -> floor lifted by default
print(f"in_wild_clock_start(active) = {clock!r}  (None == floor lifted by the source-aware fix)", flush=True)
cstart = pd.Timestamp(clock, tz="UTC") if clock else None
origins = make_origins(SNAP, START, min_followup_days=180)
snap = pd.Timestamp(SNAP, tz="UTC")
final = build_in_wild_labels(corpus, ef, SNAP)
final_pub = pd.to_datetime(final["published"], utc=True)

rows = []
for i, o in enumerate(origins):
    t = pd.Timestamp(o, tz="UTC")
    t_next = pd.Timestamp(origins[i + 1], tz="UTC") if i + 1 < len(origins) else snap
    tl = build_in_wild_labels(corpus, ef, o)
    tpub = pd.to_datetime(tl["published"], utc=True)
    tmask = tpub < t
    temask = (final_pub >= t) & (final_pub < t_next)
    if cstart is not None:
        tmask &= tpub >= cstart
        temask &= final_pub >= cstart
    train = prepare_modeling_frame(tl[tmask], features)
    test = prepare_modeling_frame(final[temask], features)
    if len(train) < 50 or len(test) < 20 or int(train["event_observed"].sum()) < 10:
        continue
    try:
        cox = fit_cox(train)
        X = test[list(cox.feature_cols_)].astype(float)
        risk = _risk_scores(cox, X, "cox")
        surv_b = survival_at(cox, X, list(HZ), "cox")
        ev_b = evaluate_survival(cox, train, test, horizons=HZ, kind="cox", surv_at_horizons=surv_b, risk=risk)
        recent = train[pd.to_datetime(train["published"], utc=True) >= (t - pd.Timedelta(days=RECENT_DAYS))]
        if int(recent["event_observed"].sum()) < 5:  # too few recent events -> use all train
            recent = train
        recal = temporal_recalibrate(cox, recent)
        surv_r = recal.survival_at(X, list(HZ))
        ev_r = evaluate_survival(cox, train, test, horizons=HZ, kind="cox", surv_at_horizons=surv_r, risk=risk)
        rows.append({
            "origin": o, "n_test_ev": int(test["event_observed"].sum()),
            "auc90_base": ev_b.get("horizon_auc", {}).get("90"),
            "auc90_recal": ev_r.get("horizon_auc", {}).get("90"),
            "ipa90_base": ev_b.get("ipa", {}).get("90"),
            "ipa90_recal": ev_r.get("ipa", {}).get("90"),
        })
        print(f"  {o} ev={rows[-1]['n_test_ev']:>4} "
              f"auc90 {rows[-1]['auc90_base']} -> {rows[-1]['auc90_recal']}  "
              f"ipa90 {rows[-1]['ipa90_base']} -> {rows[-1]['ipa90_recal']}", flush=True)
    except Exception as exc:
        print(f"  origin {o} skipped: {exc}", flush=True)


def _agg(key, fn):
    vals = [r[key] for r in rows if r.get(key) is not None]
    return float(fn(vals)) if vals else None


print(f"\norigins scored: {len(rows)}", flush=True)
print(f"MEDIAN auc90 base={_agg('auc90_base', np.median)} recal={_agg('auc90_recal', np.median)}", flush=True)
print(f"MEDIAN ipa90 base={_agg('ipa90_base', np.median)} recal={_agg('ipa90_recal', np.median)}", flush=True)
print(f"MEAN   ipa90 base={_agg('ipa90_base', np.mean)} recal={_agg('ipa90_recal', np.mean)}", flush=True)
json.dump(rows, open("artifacts/inwild_temporal_recal.json", "w"), indent=2)
print("wrote artifacts/inwild_temporal_recal.json", flush=True)
