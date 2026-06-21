"""Measure whether RECOVERING the 1,585 negative-duration (0-day, exploited-at/
before-disclosure) in-wild events — currently dropped by the default modeling
filter — helps the in-wild model. Recovery floors them to SAME_DAY_DURATION
("exploited at disclosure"), a +51% increase in usable in-wild events (3,105 ->
4,690). Honest test: does the bigger dataset improve ranking/precision, or just
add noise? Paired rolling-origin deltas (recover=True vs False), same origins.

Run: .venv/bin/python -u scripts/inwild_recover_negdur_eval.py
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.loaders import load_parquet

OUT, ART = Path("data/merged"), Path("artifacts/merged")
SNAP, START, MODEL = "2026-03-14", "2022-01-01", "xgb"


def main() -> None:
    corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
    features = pd.read_parquet(ART / "publication_features.parquet")
    event_frames = {}
    for s in ("kev", "google_0day", "vulncheck_kev", "shadowserver", "poc", "metasploit", "nuclei", "exploitdb"):
        nm, c = EVENT_SOURCES[s]
        fr = load_optional_event(OUT, nm, c)
        if fr is not None:
            event_frames[s] = (fr, c)
    origins = make_origins(SNAP, START, min_followup_days=180)
    print(f"{len(origins)} origins {origins[0]}..{origins[-1]}, model={MODEL}", flush=True)

    runs = {}
    for recover in (False, True):
        res = rolling_origin_backtest(
            corpus, event_frames, features, SNAP, origins, model=MODEL,
            label_set="in_wild", top_frac=0.1, recover_negative_duration=recover,
        )
        agg = res["aggregate"]
        ev = sum(o["n_test_events"] for o in res["per_origin"])
        runs[recover] = res
        print(f"recover={recover}: origins={agg['n_origins']} test_events={ev} "
              f"AUC@90={agg.get('horizon_auc',{}).get('90',{}).get('mean')} "
              f"PR@90={agg.get('horizon_pr_auc',{}).get('90',{}).get('mean')} "
              f"recall@top10%@90={agg.get('recall_at_top',{}).get('90',{}).get('mean')}", flush=True)

    out = {"model": MODEL, "n_origins": len(origins), "deltas_recover_vs_drop": {}}
    for metric in ("horizon_auc", "horizon_pr_auc", "recall_at_top"):
        d = paired_origin_deltas(runs[True], runs[False], metric, 90)
        out["deltas_recover_vs_drop"][metric] = d
        print(f"\nΔ {metric}@90 (recover − drop): mean={d['mean_delta']} ci={d['ci95']} "
              f"win_frac={d['win_frac']} n={d['n_paired']}", flush=True)
    (ART / "inwild_recover_negdur.json").write_text(json.dumps(out, indent=2, default=str))
    print(f"\nwrote {ART/'inwild_recover_negdur.json'}", flush=True)


if __name__ == "__main__":
    main()
