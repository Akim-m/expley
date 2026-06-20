"""VulnCheck label-lift demonstration on the in-wild head, 70/30 time split.

Builds the in-wild target two ways -- CISA-only (CISA KEV + Google 0-day, with the
2021-11-03 catalog floor) vs +VulnCheck (adds the fetched VulnCheck KEV; the floor is
dropped because VulnCheck's first-evidence dates self-heal catalog backfill) -- and fits
the production Cox model on a 70/30 time split for each, reporting the proper rare-event
metrics. Quantifies how much MORE labelled data moves the data-limited in-wild ceiling.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from temporal_exploit.cli import EVENT_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.labels import build_in_wild_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import (
    _risk_scores,
    evaluate_survival,
    fit_cox,
    prepare_modeling_frame,
    survival_at,
    time_split_frame,
)

OUT = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE = Path("data/live")
SNAP, HZ = "2026-03-14", (7, 30, 90, 180)

corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")


def event_frames(sources):
    d = {}
    for s in sources:
        name, col = EVENT_SOURCES[s]
        fr = load_optional_event(LIVE, name, col)
        if fr is None:
            fr = load_optional_event(OUT, name, col)
        if fr is not None:
            d[s] = (fr, col)
    return d


def run(sources, label):
    frames = event_frames(sources)
    labels = build_in_wild_labels(corpus, frames, SNAP)
    floor = in_wild_clock_start(tuple(frames))
    if floor is not None:
        labels = labels[pd.to_datetime(labels["published"], utc=True) >= pd.Timestamp(floor, tz="UTC")]
    frame = prepare_modeling_frame(labels, features)
    cutoff = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
    train, test = time_split_frame(frame, str(cutoff.date()))
    model = fit_cox(train)
    x = test[list(model.feature_cols_)].astype(float)
    surv = survival_at(model, x, list(HZ), "cox")
    risk = _risk_scores(model, x, "cox")
    ev = evaluate_survival(model, train, test, horizons=HZ, kind="cox",
                           surv_at_horizons=surv, risk=risk)
    out = {
        "label": label, "floor": floor, "cutoff": str(cutoff.date()),
        "n_train": len(train), "n_test": len(test), "test_events": ev["c_index_n_events"],
        "c_index": ev["c_index_ipcw"], "c_index_ci95": ev["c_index_ci95"],
        "auc": ev["horizon_auc"], "pr_auc": ev["horizon_pr_auc"], "ipa": ev["ipa"],
    }
    print(f"[{label}] floor={floor} cutoff={out['cutoff']} train={len(train)} test={len(test)} test_events={out['test_events']}")
    print(f"   c-index={out['c_index']:.3f} CI{[round(c,3) for c in out['c_index_ci95']]} "
          f"AUC@90={out['auc'].get('90'):.3f} PR-AUC@90={out['pr_auc'].get('90'):.4f} IPA@90={out['ipa'].get('90'):.4f}")
    return out


cisa = run(["kev", "google_0day"], "CISA-only")
vc = run(["kev", "google_0day", "vulncheck_kev"], "+VulnCheck")

# plot: event lift + the proper metrics, side by side
fig, ax = plt.subplots(1, 3, figsize=(15, 4.5))
fig.suptitle("VulnCheck label lift on the in-wild head (70/30 time split, Cox)", fontweight="bold")
labels2 = ["CISA-only", "+VulnCheck"]
colors = ["#7f7f7f", "#2ca02c"]
ax[0].bar(labels2, [cisa["test_events"], vc["test_events"]], color=colors)
ax[0].set_title("(a) test-set in-wild EVENTS\nmore positives = the only ceiling lever")
for i, n in enumerate([cisa["test_events"], vc["test_events"]]):
    ax[0].text(i, n, f"{n}", ha="center", va="bottom", fontweight="bold")
ax[1].bar([f"{l}\n{h}d" for l in labels2 for h in ["90"]], [cisa["auc"].get("90"), vc["auc"].get("90")], color=colors)
ax[1].axhline(0.5, ls="--", c="grey"); ax[1].set_ylim(0, 1); ax[1].set_title("(b) AUC@90 — ranking (was already strong)")
prc, prv = cisa["pr_auc"].get("90"), vc["pr_auc"].get("90")
ax[2].bar(labels2, [prc, prv], color=colors); ax[2].set_title("(c) PR-AUC@90 — precision\n(rises with more positives)")
for i, n in enumerate([prc, prv]):
    ax[2].text(i, n, f"{n:.3f}", ha="center", va="bottom", fontweight="bold")
plt.tight_layout(rect=[0, 0, 1, 0.93])
Path("artifacts/reports").mkdir(parents=True, exist_ok=True)
fig.savefig("artifacts/reports/vulncheck_lift.png", dpi=130, bbox_inches="tight")
json.dump({"cisa": cisa, "vulncheck": vc}, open("artifacts/reports/vulncheck_lift.json", "w"), indent=2, default=str)
print("\nwrote artifacts/reports/vulncheck_lift.png + .json")
