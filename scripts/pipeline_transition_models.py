"""RQ2 cont. — model each forward pipeline transition (PoC -> MSF / Nuclei / KEV)
on the clock-restarted (post-PoC) cohort: who advances, how fast, what predicts it.
Cause-specific (competing sources censor), time-based split, Cox + XGBoost-AFT,
held-out transition c-index. Mirrors scripts/transition_poc_to_exploitdb.py (N6).

PoC-date artifact (see pipeline_cascade_characterization.py): the git-mined PoC
date is a bulk-index date for older CVEs, so the PoC clock origin is only trustworthy
for recent CVEs. Restrict to published >= MIN_PUB_YEAR; report both the restricted
and all-CVE event counts so the artifact's effect on the transition cohort is visible.
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import _fit
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import build_transition_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import (
    _risk_scores,
    prepare_modeling_frame,
    time_split_frame,
    transition_cindex,
)

OUT = Path("data/merged")
SNAP = "2026-03-14"
MIN_PUB = "2021-01-01"  # PoC clock origin trustworthy only for recent CVEs (artifact)
TARGETS = ["metasploit", "nuclei", "kev"]
COMPETING = {"metasploit": ("nuclei", "kev"), "nuclei": ("metasploit", "kev"), "kev": ("metasploit", "nuclei")}

corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
feats = pd.read_parquet("artifacts/merged/publication_features.parquet")
frames = {}
for s in ["poc", *TARGETS]:
    name, col = EVENT_SOURCES[s]
    fr = load_optional_event(OUT, name, col)
    if fr is not None:
        frames[s] = (fr, col)

results = {}
for tgt in TARGETS:
    comp = tuple(c for c in COMPETING[tgt] if c in frames)
    labels = build_transition_labels(corpus, frames, SNAP, from_source="poc", to_source=tgt, competing_sources=comp)
    frame_all = prepare_modeling_frame(labels, feats)
    n_ev_all = int(frame_all["event_observed"].sum())
    # restrict to the clean recent cohort (trustworthy PoC clock origin)
    pub = pd.to_datetime(frame_all["published"], utc=True)
    frame = frame_all[pub >= pd.Timestamp(MIN_PUB, tz="UTC")].reset_index(drop=True)
    n_ev = int(frame["event_observed"].sum())
    row = {"n_eligible_recent": len(frame), "n_events_recent": n_ev, "n_events_all": n_ev_all}
    if n_ev > 0:
        row["median_lag_days"] = float(frame.loc[frame["event_observed"].astype(bool), "duration_days"].median())
        cutoff = pub[pub >= pd.Timestamp(MIN_PUB, tz="UTC")].quantile(0.70)
        train, test = time_split_frame(frame, str(cutoff.date()))
        for kind in ("cox", "xgb"):
            try:
                model = _fit(kind, train)
                x = test[list(model.feature_cols_)].astype(float)
                risk = _risk_scores(model, x, kind)
                row[f"{kind}_cindex"] = transition_cindex(
                    test["duration_days"].to_numpy(), risk, test["event_observed"].to_numpy().astype(bool))
            except Exception as e:
                row[f"{kind}_cindex"] = None
                row[f"{kind}_error"] = str(e)[:120]
    results[f"poc_to_{tgt}"] = row
    print(f"poc->{tgt}: events recent={n_ev} (all={n_ev_all}) "
          f"median_lag={row.get('median_lag_days')} cox_c={row.get('cox_cindex')} xgb_c={row.get('xgb_cindex')}",
          flush=True)

Path("artifacts/merged").mkdir(parents=True, exist_ok=True)
Path("artifacts/merged/pipeline_transitions.json").write_text(json.dumps(results, indent=2, default=str))
print("\nwrote artifacts/merged/pipeline_transitions.json", flush=True)
