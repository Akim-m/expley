"""Full in-wild wiring: every in-wild source (CISA KEV + Google 0-day + VulnCheck KEV) PLUS
0-day recovery -- negative-duration events (exploited at/before disclosure) floored to day-0
instead of dropped. 3-way 70/30 Cox comparison: CISA-only -> +VulnCheck -> +VulnCheck+0day.
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


def run(sources, recover, label):
    frames = event_frames(sources)
    labels = build_in_wild_labels(corpus, frames, SNAP)
    floor = in_wild_clock_start(tuple(frames))
    if floor is not None:
        labels = labels[pd.to_datetime(labels["published"], utc=True) >= pd.Timestamp(floor, tz="UTC")]
    frame = prepare_modeling_frame(labels, features, recover_negative_duration=recover)
    cutoff = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
    train, test = time_split_frame(frame, str(cutoff.date()))
    model = fit_cox(train)
    x = test[list(model.feature_cols_)].astype(float)
    surv = survival_at(model, x, list(HZ), "cox")
    risk = _risk_scores(model, x, "cox")
    ev = evaluate_survival(model, train, test, horizons=HZ, kind="cox", surv_at_horizons=surv, risk=risk)
    out = {
        "label": label, "recover": recover,
        "train_events": int(train["event_observed"].sum()), "test_events": ev["c_index_n_events"],
        "c_index": ev["c_index_ipcw"], "ci": ev["c_index_ci95"],
        "auc": ev["horizon_auc"], "pr": ev["horizon_pr_auc"], "ipa": ev["ipa"],
    }
    print(f"[{label}] train_ev={out['train_events']} test_ev={out['test_events']} "
          f"c-index={out['c_index']:.3f} CI{[round(c, 3) for c in out['ci']]} "
          f"AUC@90={out['auc'].get('90'):.3f} PR-AUC@90={out['pr'].get('90'):.4f} IPA@90={out['ipa'].get('90'):.4f}",
          flush=True)
    return out


arms = [
    run(["kev", "google_0day"], False, "CISA-only"),
    run(["kev", "google_0day", "vulncheck_kev"], False, "+VulnCheck"),
    run(["kev", "google_0day", "vulncheck_kev"], True, "+VulnCheck +0day"),
]

names = [a["label"] for a in arms]
x = np.arange(len(names))
colors = ["#7f7f7f", "#2ca02c", "#1f77b4"]
fig, ax = plt.subplots(2, 2, figsize=(13, 9))
fig.suptitle("Full in-wild wiring: all sources + 0-day recovery (70/30 Cox)", fontweight="bold")
ax[0, 0].bar(x - 0.2, [a["train_events"] for a in arms], 0.4, label="train", color="#aaaaaa")
ax[0, 0].bar(x + 0.2, [a["test_events"] for a in arms], 0.4, label="test", color="#333333")
ax[0, 0].set_title("(a) in-wild EVENTS (train/test)"); ax[0, 0].set_xticks(x); ax[0, 0].set_xticklabels(names, fontsize=8); ax[0, 0].legend(fontsize=8)
for i, a in enumerate(arms):
    ax[0, 0].text(i + 0.2, a["test_events"], str(a["test_events"]), ha="center", va="bottom", fontsize=8, fontweight="bold")
ax[0, 1].bar(x, [a["c_index"] for a in arms], color=colors)
ax[0, 1].errorbar(x, [a["c_index"] for a in arms],
                  yerr=[[a["c_index"] - a["ci"][0] for a in arms], [a["ci"][1] - a["c_index"] for a in arms]],
                  fmt="none", ecolor="k", capsize=5)
ax[0, 1].axhline(0.5, ls="--", c="grey"); ax[0, 1].set_ylim(0, 1); ax[0, 1].set_title("(b) c-index (+95% CI) — CI tightens with data"); ax[0, 1].set_xticks(x); ax[0, 1].set_xticklabels(names, fontsize=8)
ax[1, 0].bar(x, [a["pr"].get("90") for a in arms], color=colors)
ax[1, 0].set_title("(c) PR-AUC@90 — precision"); ax[1, 0].set_xticks(x); ax[1, 0].set_xticklabels(names, fontsize=8)
ax[1, 1].bar(x, [a["ipa"].get("90") for a in arms], color=colors)
ax[1, 1].axhline(0, c="k"); ax[1, 1].set_title("(d) IPA@90 — calibration value"); ax[1, 1].set_xticks(x); ax[1, 1].set_xticklabels(names, fontsize=8)
plt.tight_layout(rect=[0, 0, 1, 0.95])
Path("artifacts/reports").mkdir(parents=True, exist_ok=True)
fig.savefig("artifacts/reports/inwild_full_wiring.png", dpi=130, bbox_inches="tight")
json.dump(arms, open("artifacts/reports/inwild_full_wiring.json", "w"), indent=2, default=str)
print("\nwrote artifacts/reports/inwild_full_wiring.png + .json")
