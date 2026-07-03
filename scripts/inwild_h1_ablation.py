"""Ablation: does a leakage-safe HackerOne flag add in-wild ranking lift OVER the
structural model (not just over EPSS-alone)?

Feature = `h1_pub_report`: 1 if a PUBLICLY DISCLOSED HackerOne bug-bounty report
referencing this CVE existed on/before the CVE's publication date (disclosed_at <=
published) — publication-time-knowable, so leakage-safe. Everything else mirrors
`scripts/inwild_epss_parity.py`: same corpus, same in-wild target, same walk-forward
origins, same model (xgb-AFT), structural feature set with NO EPSS. Only the extra
column changes, so any AUC delta is attributable to the flag.

Companion: docs/hackerone_epss_reconciliation_2026-07.md.
Prediction (pre-registered): ~null, <= +0.005 AUC@30 — sparse (~0.2% of corpus) and
largely redundant with CVSS/CWE/PoC structural features.

Run: .venv/bin/python scripts/inwild_h1_ablation.py
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.epss_features import epss_feature_columns
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
ARTIFACT_DIR = "artifacts/bt_epss"
H1_JSON = Path("artifacts/hackerone_cve_reports.json")
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
MODEL = "xgb"

# ---- load corpus + in-wild event frames (mirror the parity script exactly) ----
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
print(f"in-wild sources: {sorted(event_frames)}", flush=True)

features_full = pd.read_parquet(f"{ARTIFACT_DIR}/publication_features.parquet")
epss_cols = epss_feature_columns(features_full.columns)
structural = features_full.drop(columns=epss_cols)

# ---- build the leakage-safe H1 flag: public report disclosed <= CVE publication ----
rows = json.loads(H1_JSON.read_text())
dis = {}
for r in rows:
    d = pd.to_datetime(r.get("disclosed_at"), utc=True, errors="coerce")
    if pd.isna(d):
        continue
    for c in (r.get("cve_ids") or []):
        c = c.strip().upper()
        dis[c] = min(dis.get(c, d), d)
h1_first = pd.Series(dis, name="h1_disclosed_at")

pub = structural[["cve_id", "published"]].copy()
pub["cve_id"] = pub["cve_id"].astype(str).str.upper()
pub["published"] = pd.to_datetime(pub["published"], utc=True, errors="coerce")
pub = pub.join(h1_first, on="cve_id")
flag = ((pub["h1_disclosed_at"].notna()) & (pub["h1_disclosed_at"] <= pub["published"])).astype("int8")
structural_plus = structural.copy()
structural_plus["h1_pub_report"] = flag.to_numpy()

n_flag = int(structural_plus["h1_pub_report"].sum())
assert n_flag > 0, "flag is all-zero — join/leakage-window bug"
assert "h1_pub_report" not in structural.columns
print(f"leakage-safe flag prevalence: {n_flag}/{len(structural_plus)} "
      f"({100*n_flag/len(structural_plus):.3f}% of corpus)", flush=True)

origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))
print(f"model={MODEL} origins={len(origins)}", flush=True)

common = dict(snapshot_date=SNAPSHOT, origins=origins, model=MODEL,
              label_set="in_wild", horizons=HORIZONS, clock_start=clock_start)
res_base = rolling_origin_backtest(corpus, event_frames, structural, **common)
res_plus = rolling_origin_backtest(corpus, event_frames, structural_plus, **common)


def _auc(r, metric, h):
    return r["aggregate"].get(metric, {}).get(str(h), {}).get("mean")


out = {
    "feature": "h1_pub_report (disclosed_at <= published; leakage-safe)",
    "flag_prevalence": n_flag, "n_origins": len(origins),
    "test_events_total": res_base["aggregate"]["test_events_total"],
    "baseline_structural": {f"auc_{h}": _auc(res_base, "horizon_auc", h) for h in (30, 90)},
    "structural_plus_h1": {f"auc_{h}": _auc(res_plus, "horizon_auc", h) for h in (30, 90)},
    "paired_delta": {
        f"{m}_{h}": paired_origin_deltas(res_plus, res_base, m, h)
        for m in ("horizon_auc", "horizon_pr_auc") for h in (30, 90)
    },
}
Path("artifacts").mkdir(exist_ok=True)
Path("artifacts/inwild_h1_ablation.json").write_text(json.dumps(out, indent=2, default=str))

d30 = out["paired_delta"]["horizon_auc_30"]
d90 = out["paired_delta"]["horizon_auc_90"]
b, p = out["baseline_structural"], out["structural_plus_h1"]
print(f"\n=== H1 flag ablation (in-wild, {out['n_origins']} origins, "
      f"{out['test_events_total']} test events) ===")
print(f"AUC@30  structural {b['auc_30']:.4f} -> +h1 {p['auc_30']:.4f}   "
      f"delta {d30['mean_delta']:+.4f} CI {d30['ci95']}")
print(f"AUC@90  structural {b['auc_90']:.4f} -> +h1 {p['auc_90']:.4f}   "
      f"delta {d90['mean_delta']:+.4f} CI {d90['ci95']}")
print("wrote artifacts/inwild_h1_ablation.json")
