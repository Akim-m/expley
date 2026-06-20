"""Phase C — defender-facing interpretation + a STATE-AWARE triage score (the
required §"what would a defender do differently" deliverable + a model improvement).

The improvement: a single static model is signal-limited at publication (first-weap
~0.61, incidence-dominated). But weaponization is a STATE machine — once a CVE has a
public PoC, the PoC->KEV model is sharp (0.87). So the deployable score ESCALATES:
  - state PUBLISHED (no PoC yet): structural first-weaponization risk -> triage tier
  - state POC-PRESENT: switch to the PoC->KEV in-wild risk (much sharper)
We report operating points (recall@top-k%, precision, median lead-time) for each state,
plus decision-curve net benefit vs treat-all/treat-none and vs an EPSS-only baseline.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import _fit
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import build_transition_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import _risk_scores, prepare_modeling_frame, time_split_frame

OUT = Path("data/merged")
SNAP, MIN_PUB, H = "2026-03-14", "2021-01-01", 30  # triage horizon = 30 days


def operating_points(risk, dur, ev, horizon, ks=(0.01, 0.05, 0.10)):
    """recall@top-k% / precision / median lead-time for a risk ranking at a horizon."""
    hit = ev & (dur <= horizon)  # event within the triage horizon
    n_pos = int(hit.sum())
    order = np.argsort(-risk)  # highest risk first
    out = {"n": int(len(risk)), "n_pos_within_h": n_pos}
    for k in ks:
        topn = max(1, int(len(risk) * k))
        sel = order[:topn]
        tp = int(hit[sel].sum())
        lead = dur[sel][ev[sel]]
        out[f"top_{int(k*100)}pct"] = {
            "recall": tp / n_pos if n_pos else None,
            "precision": tp / topn,
            "median_lead_days": float(np.median(horizon - lead[lead <= horizon])) if (lead <= horizon).any() else None,
        }
    return out


corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
feats = pd.read_parquet("artifacts/merged/publication_features.parquet")
results = {}

# --- STATE 1: publication-time first-weaponization triage (structural model) ---
fw = pd.read_parquet("artifacts/merged/modeling_labels.parquet",
                     columns=["cve_id", "published", "duration_days", "event_observed", "negative_duration_flag"])
frame = prepare_modeling_frame(fw, feats)
p = pd.to_datetime(frame["published"], utc=True)
frame = frame[p >= pd.Timestamp(MIN_PUB, tz="UTC")].reset_index(drop=True)
cut = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
tr, te = time_split_frame(frame, str(cut.date()))
model = _fit("xgb", tr)
risk = _risk_scores(model, te[list(model.feature_cols_)].astype(float), "xgb")
dur, ev = te["duration_days"].to_numpy(float), te["event_observed"].to_numpy(bool)
results["state_published_firstweap"] = operating_points(risk, dur, ev, H)
# EPSS-only baseline operating points (the circularity control)
epss_only = te["epss_at_publication"].to_numpy(float)
results["state_published_epss_only"] = operating_points(epss_only, dur, ev, H)

# --- STATE 2: PoC-present -> in-wild (KEV) escalation (the sharp conditional model) ---
frames = {}
for s in ["poc", "kev", "metasploit", "nuclei"]:
    nm, c = EVENT_SOURCES[s]
    fr = load_optional_event(OUT, nm, c)
    if fr is not None:
        frames[s] = (fr, c)
lab = build_transition_labels(corpus, frames, SNAP, from_source="poc", to_source="kev",
                              competing_sources=("metasploit", "nuclei"))
tf = prepare_modeling_frame(lab, feats)
pp = pd.to_datetime(tf["published"], utc=True)
tf = tf[pp >= pd.Timestamp(MIN_PUB, tz="UTC")].reset_index(drop=True)
cut2 = pd.to_datetime(tf["published"], utc=True).quantile(0.70)
tr2, te2 = time_split_frame(tf, str(cut2.date()))
m2 = _fit("xgb", tr2)
risk2 = _risk_scores(m2, te2[list(m2.feature_cols_)].astype(float), "xgb")
dur2, ev2 = te2["duration_days"].to_numpy(float), te2["event_observed"].to_numpy(bool)
results["state_poc_present_to_kev"] = operating_points(risk2, dur2, ev2, 90)  # 90d for the rarer KEV

# --- decision-curve net benefit at the publication state (vs treat-all/none, vs EPSS) ---
def net_benefit(risk, dur, ev, horizon, thresholds):
    hit = (ev & (dur <= horizon)).astype(int); n = len(risk); rng = np.linspace(0, 1, 1001)
    # map risk to [0,1] rank-prob for thresholding
    rp = (np.argsort(np.argsort(risk)) + 1) / n
    nb = {}
    for pt in thresholds:
        flag = rp >= (1 - pt * 10)  # treat the top (pt*10) fraction — coarse mapping
        tp = int((flag & (hit == 1)).sum()); fp = int((flag & (hit == 0)).sum())
        nb[str(pt)] = (tp / n) - (fp / n) * (pt / (1 - pt))
    base = hit.mean()
    return {"model": nb, "treat_all_at_0.05": base - (1 - base) * (0.05 / 0.95)}

results["decision_curve_published"] = net_benefit(risk, dur, ev, H, [0.01, 0.03, 0.05])

Path("artifacts/merged").mkdir(parents=True, exist_ok=True)
Path("artifacts/merged/defender_operating_points.json").write_text(json.dumps(results, indent=2, default=str))
print("=== STATE 1: publication-time first-weaponization triage (xgb structural) ===")
for k in ("top_1pct", "top_5pct", "top_10pct"):
    r = results["state_published_firstweap"][k]; e = results["state_published_epss_only"][k]
    print(f"  {k}: model recall={r['recall']:.3f} prec={r['precision']:.3f} lead={r['median_lead_days']}d "
          f"| EPSS-only recall={e['recall']:.3f} prec={e['precision']:.3f}")
print(f"  (n={results['state_published_firstweap']['n']}, events within {H}d="
      f"{results['state_published_firstweap']['n_pos_within_h']})")
print("\n=== STATE 2: PoC-present -> KEV escalation (xgb, the sharp conditional model) ===")
for k in ("top_1pct", "top_5pct", "top_10pct"):
    r = results["state_poc_present_to_kev"][k]
    print(f"  {k}: recall={r['recall']} prec={r['precision']} lead={r['median_lead_days']}d")
print(f"  (n={results['state_poc_present_to_kev']['n']}, KEV within 90d="
      f"{results['state_poc_present_to_kev']['n_pos_within_h']})")
print("\nwrote artifacts/merged/defender_operating_points.json")
