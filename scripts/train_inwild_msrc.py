"""Train the in-wild model on the MSRC-expanded labels with a 70/30 TIME split.

In-wild label set = kev + google_0day + vulncheck_kev + (NEW) msrc, earliest-date
wins. 70/30 split on `published` (train = earliest 70%, test = latest 30%), clean
recent cohort (published >= 2021) to avoid the pre-2021 catalog backfill artifact.
Recovers negative-duration 0-days (exploited at/before disclosure). xgb-AFT on GPU.
Reports with-vs-without MSRC so the (honestly marginal) lift is explicit.

Run: .venv/bin/python -u scripts/train_inwild_msrc.py
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import _fit
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import IN_WILD_SOURCES, build_in_wild_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import (
    _risk_scores,
    evaluate_survival,
    prepare_modeling_frame,
    survival_at,
    time_split_frame,
)

OUT, ART = Path("data/merged"), Path("artifacts/merged")
SNAP, MIN_PUB, SPLIT = "2026-03-14", "2021-01-01", 0.70
HORIZONS = (7, 30, 90, 180)


def build_frame(sources):
    corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
    feats = pd.read_parquet(ART / "publication_features.parquet")
    ef = {}
    for s in sources:
        nm, c = EVENT_SOURCES[s]
        fr = load_optional_event(OUT, nm, c)
        if fr is not None:
            ef[s] = (fr, c)
    labels = build_in_wild_labels(corpus, ef, SNAP)
    frame = prepare_modeling_frame(labels, feats, recover_negative_duration=True)
    return frame[pd.to_datetime(frame["published"], utc=True) >= pd.Timestamp(MIN_PUB, tz="UTC")].reset_index(drop=True)


def train_eval(frame, tag):
    cut = pd.to_datetime(frame["published"], utc=True).quantile(SPLIT)
    train, test = time_split_frame(frame, str(cut.date()))
    model = _fit("xgb", train)
    X = test[list(model.feature_cols_)].astype(float)
    surv = survival_at(model, X, list(HORIZONS), "xgb")
    risk = _risk_scores(model, X, "xgb")
    ev = evaluate_survival(model, train, test, horizons=HORIZONS, kind="xgb", surv_at_horizons=surv, risk=risk)
    res = {
        "tag": tag, "cut": str(cut.date()),
        "n_train": len(train), "n_train_events": int(train.event_observed.sum()),
        "n_test": len(test), "n_test_events": int(test.event_observed.sum()),
        "c_index_ipcw": ev.get("c_index_ipcw"), "c_index_ci95": ev.get("c_index_ci95"),
        "integrated_brier": ev.get("integrated_brier"),
        "pr_auc": ev.get("horizon_pr_auc", {}), "auc": ev.get("horizon_auc", {}),
    }
    print(f"\n=== {tag} (70/30 split at {res['cut']}) ===", flush=True)
    print(f"  train n={res['n_train']} ev={res['n_train_events']} | test n={res['n_test']} ev={res['n_test_events']}", flush=True)
    print(f"  c-index(IPCW)={res['c_index_ipcw']:.4f} CI={[round(x,3) for x in (res['c_index_ci95'] or [0,0])]} IBS={res['integrated_brier']}", flush=True)
    print(f"  AUC@90={res['auc'].get(90)}  PR-AUC@90={res['pr_auc'].get(90)}", flush=True)
    return res


def main() -> None:
    print(f"IN_WILD_SOURCES = {IN_WILD_SOURCES}", flush=True)
    without = [s for s in IN_WILD_SOURCES if s != "msrc"]
    f_with = build_frame(IN_WILD_SOURCES)
    f_without = build_frame(without)
    print(f"in-wild events (recovered): with MSRC={int(f_with.event_observed.sum())} "
          f"without MSRC={int(f_without.event_observed.sum())} "
          f"(Δ={int(f_with.event_observed.sum())-int(f_without.event_observed.sum())})", flush=True)
    r_with = train_eval(f_with, "with MSRC")
    r_without = train_eval(f_without, "without MSRC")
    out = {"split": SPLIT, "min_pub": MIN_PUB, "with_msrc": r_with, "without_msrc": r_without}
    (ART / "train_inwild_msrc.json").write_text(json.dumps(out, indent=2, default=str))
    print(f"\nΔ c-index (with − without MSRC) = {r_with['c_index_ipcw'] - r_without['c_index_ipcw']:+.4f}", flush=True)
    print(f"wrote {ART/'train_inwild_msrc.json'}", flush=True)


if __name__ == "__main__":
    main()
