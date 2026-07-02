"""A/B: xgb AFT default (500 rounds, no early stop) vs early_stopping_rounds=50
with the random event-stratified split, on the standard 15-origin in-wild
backtest. Adoption gate: paired AUC@30/@90 deltas whose CI does not sit below 0,
plus measured wall-clock. Writes artifacts/xgb_earlystop_ab.json."""
import json
import time
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAPSHOT, START = "2026-03-14", "2022-01-01"
corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
event_frames = {}
for source, (parquet_name, date_col) in EVENT_SOURCES.items():
    if source not in IN_WILD_SOURCES:
        continue
    frame = load_optional_event(OUT_DIR, parquet_name, date_col)
    if frame is not None:
        event_frames[source] = (frame, date_col)
features = pd.read_parquet("artifacts/publication_features.parquet")
origins = make_origins(SNAPSHOT, START, min_followup_days=180)
clock_start = in_wild_clock_start(tuple(event_frames))


def run(tag, model_kwargs):
    t0 = time.perf_counter()
    res = rolling_origin_backtest(
        corpus, event_frames, features, SNAPSHOT, origins, model="xgb",
        label_set="in_wild", clock_start=clock_start, model_kwargs=model_kwargs,
    )
    res["wall_s"] = round(time.perf_counter() - t0, 1)
    print(tag, "wall_s:", res["wall_s"], flush=True)
    return res


base = run("baseline", None)
fast = run("earlystop", {"early_stopping_rounds": 50, "validation": "random"})
out = {
    "wall_s": {"baseline": base["wall_s"], "earlystop": fast["wall_s"]},
    "deltas_earlystop_minus_base": {
        f"auc_{h}": paired_origin_deltas(fast, base, "horizon_auc", h) for h in (30, 90)
    },
}
Path("artifacts/xgb_earlystop_ab.json").write_text(json.dumps(out, indent=2))
print(json.dumps(out["deltas_earlystop_minus_base"], indent=2))
