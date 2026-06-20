"""Does the CISA-inherited clock floor (published>=2021-11-03) help or hurt the
+VulnCheck in-wild model?

The floor exists to drop CISA's 2021-11-03 catalog-launch backfill spike (287 entries
that day). VulnCheck dates are first-*evidence* (no such spike: 53 on that day, smooth
back to 2000), so the floor wrongly discards ~1,700 valid VulnCheck training events.
Test sets are identical across arms (origins start 2022-01-01 => test CVEs always
published >=2022), so any AUC delta is a pure training-set effect.

Result (this session): no-floor improves AUC@90 median 0.808->0.827 (paired delta
+0.0147, CI [+0.0012,+0.0281] excludes 0), lifts recall, and erases the IPA@90 mean
collapse (-0.0835 -> +0.0011). A VulnCheck-only arm reproduces it.
"""
import json
import traceback
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import IN_WILD_SOURCES
from temporal_exploit.loaders import load_parquet

OUT = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
SNAP, START, HZ = "2026-03-14", "2022-01-01", (7, 30, 90, 180)
corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
features = pd.read_parquet("artifacts/bt_epss/publication_features.parquet")
origins = make_origins(SNAP, START, min_followup_days=180)


def frames(vc_only=False):
    ef = {}
    for s in IN_WILD_SOURCES:
        if s == "vulncheck_kev":
            ef[s] = (pd.read_parquet("data/live/vulncheck_kev.parquet"), "vulncheck_kev_date_added"); continue
        if vc_only:
            continue
        if s in EVENT_SOURCES:
            pq, dc = EVENT_SOURCES[s]
            fr = load_optional_event(OUT, pq, dc)
            if fr is not None:
                ef[s] = (fr, dc)
    return ef


arms = [("floor", frames(), "2021-11-03"), ("nofloor", frames(), None),
        ("vconly_nofloor", frames(vc_only=True), None)]
res, runs = {}, {}
for tag, ef, clk in arms:
    try:
        r = rolling_origin_backtest(corpus, ef, features, SNAP, origins, model="cox",
                                    label_set="in_wild", horizons=HZ, clock_start=clk)
        runs[tag] = r
        a = r["aggregate"]
        def g(m, h, a=a):
            return a.get(m, {}).get(str(h), {})
        res[tag] = {"clock": clk, "events": a["test_events_total"], "auc90": g("horizon_auc", 90),
                    "recall90": g("recall_at_top", 90), "ipa90": g("ipa", 90),
                    "lead": a.get("lead_time_days_median")}
        print(f"{tag}: ev={a['test_events_total']} auc90_med={g('horizon_auc',90).get('median'):.4f} "
              f"recall90={g('recall_at_top',90).get('mean'):.4f} "
              f"ipa90_med={g('ipa',90).get('median'):+.4f} mean={g('ipa',90).get('mean'):+.4f} "
              f"lead={a.get('lead_time_days_median')}", flush=True)
        json.dump(res, open("artifacts/inwild_floor_ablation.json", "w"), indent=2)
    except Exception:
        print(f"{tag}: FAILED\n{traceback.format_exc()}", flush=True)
for tag in ("nofloor", "vconly_nofloor"):
    if tag in runs and "floor" in runs:
        d = paired_origin_deltas(runs[tag], runs["floor"], "horizon_auc", 90)
        print(f"paired {tag}-floor auc90 delta={d['mean_delta']:+.4f} ci95={d['ci95']}", flush=True)
print("DONE", flush=True)
