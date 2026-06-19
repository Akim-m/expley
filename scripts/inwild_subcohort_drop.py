"""Honesty check for the censoring-free horizon-AUC.

The horizon-AUC restricts to the "fully-observed subcohort" {event OR
followed >= h days}. The survival-evaluation literature warns this can induce
informative-observation (selection) bias — UNLESS almost nobody is dropped. In
this backtest each origin's test cohort is scored against the *final* snapshot,
and `make_origins(min_followup_days=180)` keeps the last origin >=180d before the
snapshot, so for horizons <=180 the drop should be tiny. This quantifies it: the
% of in-wild test CVEs the subcohort restriction removes, per horizon, pooled
over origins. A small number means the headline AUC is not selection-biased.
"""
import pandas as pd

from temporal_exploit.backtest import make_origins
from temporal_exploit.cli import (
    EVENT_SOURCES,
    IN_WILD_SOURCES,
    in_wild_clock_start,
    load_optional_event,
)
from temporal_exploit.labels import build_in_wild_labels
from temporal_exploit.loaders import load_parquet
from pathlib import Path

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAPSHOT, START, HORIZONS = "2026-03-14", "2022-01-01", (7, 30, 90, 180)

corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)

snap = pd.Timestamp(SNAPSHOT, tz="UTC")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
active = tuple(s for s in event_frames if s in IN_WILD_SOURCES)
cstart = pd.Timestamp(in_wild_clock_start(active), tz="UTC")
final = build_in_wild_labels(corpus, event_frames, SNAPSHOT)
final_pub = pd.to_datetime(final["published"], utc=True)

pooled = {h: [0, 0, 0] for h in HORIZONS}  # [n_test, n_dropped, n_dropped_among_nonevent]
for i, origin in enumerate(origins):
    t = pd.Timestamp(origin, tz="UTC")
    t_next = pd.Timestamp(origins[i + 1], tz="UTC") if i + 1 < len(origins) else snap
    mask = (final_pub >= t) & (final_pub < t_next) & (final_pub >= cstart)
    sub = final[mask]
    dur = sub["duration_days"].to_numpy(float)
    obs = sub["event_observed"].to_numpy(bool)
    for h in HORIZONS:
        dropped = (~obs) & (dur < h)  # censored before h -> removed from the subcohort
        pooled[h][0] += len(sub)
        pooled[h][1] += int(dropped.sum())

print(f"in_wild test cohorts pooled over {len(origins)} origins (clock_start={cstart.date()}):")
for h in HORIZONS:
    n, d, _ = pooled[h]
    print(f"  h={h:>3}d: {d:>5}/{n:<6} dropped by subcohort restriction = {100 * d / n:5.2f}%")
