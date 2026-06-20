"""Is the VulnCheck IPA@90 "collapse" systematic, or one event-starved origin?

The +VulnCheck in-wild backtest reports mean IPA@90 = -0.0835 (vs baseline -0.003),
which reads like a calibration disaster. But mean IPA is fragile to event-starved
origins. This dumps per-origin IPA@90 + median + the paired delta so the honest
question is answered: median IPA@90 stays ~0; the mean is dragged by ONE origin
(2022-04, IPA -1.17, 98 events); the paired CI [-0.237,+0.076] includes 0. So
VulnCheck does NOT systematically worsen calibration -- but 2022-04 is a real,
large origin (the first big post-backfill test window) worth understanding.

Writes artifacts/vulncheck_diagnose.json.
"""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, in_wild_clock_start, load_optional_event
from temporal_exploit.labels import IN_WILD_SOURCES
from temporal_exploit.loaders import load_parquet

OUT = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAP, START, HZ = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
origins = make_origins(SNAP, START, min_followup_days=180)


def frames(include_vc):
    ef = {}
    for s in IN_WILD_SOURCES:
        if s == "vulncheck_kev":
            if include_vc:
                ef[s] = (pd.read_parquet("data/live/vulncheck_kev.parquet"), "vulncheck_kev_date_added")
            continue
        if s in EVENT_SOURCES:
            pq, dc = EVENT_SOURCES[s]
            fr = load_optional_event(OUT, pq, dc)
            if fr is not None:
                ef[s] = (fr, dc)
    return ef


res, runs = {}, {}
for tag, inc in [("baseline", False), ("vulncheck", True)]:
    ef = frames(inc)
    clock = in_wild_clock_start(tuple(ef))
    r = rolling_origin_backtest(corpus, ef, features, SNAP, origins, model="cox",
                                label_set="in_wild", horizons=HZ, clock_start=clock)
    runs[tag] = r
    a = r["aggregate"]
    res[tag] = {"clock_start": clock, "test_events_total": a["test_events_total"],
                "ipa90": a["ipa"].get("90"), "auc90": a["horizon_auc"].get("90"),
                "lead": a.get("lead_time_days_median"),
                "per_origin": [{"origin": o["origin"], "n_ev": o["n_test_events"],
                                "ipa90": o["ipa"].get("90"), "auc90": o["horizon_auc"].get("90")}
                               for o in r["per_origin"]]}
res["paired_ipa90"] = paired_origin_deltas(runs["vulncheck"], runs["baseline"], "ipa", 90)
res["paired_auc90"] = paired_origin_deltas(runs["vulncheck"], runs["baseline"], "horizon_auc", 90)
json.dump(res, open("artifacts/vulncheck_diagnose.json", "w"), indent=2)
for tag in ("baseline", "vulncheck"):
    a = res[tag]
    print(f"{tag}: events={a['test_events_total']} ipa90 mean={a['ipa90']['mean']:+.4f} "
          f"median={a['ipa90']['median']:+.4f} auc90 mean={a['auc90']['mean']:.4f} lead={a['lead']}", flush=True)
print("paired vc-baseline ipa90: mean_delta=%.4f ci95=%s" %
      (res['paired_ipa90']['mean_delta'], res['paired_ipa90']['ci95']), flush=True)
