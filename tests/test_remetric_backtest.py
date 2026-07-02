"""A1 re-metric, Task 1: top_fracs passthrough + caveated IPCW aggregation.

Uses a tiny synthetic corpus large enough to clear the backtest's min_train /
min_test / min_train_events gates on at least one origin.
"""
import numpy as np
import pandas as pd

from temporal_exploit.backtest import rolling_origin_backtest


def _world(n=600, seed=0):
    rng = np.random.default_rng(seed)
    pub = pd.to_datetime("2021-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 900, size=n), unit="D"
    )
    corpus = pd.DataFrame({"cve_id": [f"CVE-{i}" for i in range(n)], "published": pub})
    x = rng.normal(size=n)
    # events cluster on high-x rows; ~25% event rate, lag 5-200d after publication
    is_event = rng.random(n) < (0.15 + 0.2 * (x > 0))
    lag = rng.integers(5, 200, size=n)
    events = pd.DataFrame({
        "cve_id": corpus["cve_id"][is_event],
        "date_added": (pub + pd.to_timedelta(lag, unit="D"))[is_event],
    })
    features = pd.DataFrame({"cve_id": corpus["cve_id"], "x": x,
                             "noise": rng.normal(size=n)})
    return corpus, {"kev": (events, "date_added")}, features


def test_top_fracs_passthrough_and_ipcw_aggregate():
    corpus, event_frames, features = _world()
    res = rolling_origin_backtest(
        corpus, event_frames, features, snapshot_date="2024-06-01",
        origins=["2022-07-01", "2023-01-01"], model="cox", label_set="in_wild",
        horizons=(30, 90), min_train=50, min_train_events=10, min_test=20,
        top_fracs=(0.02, 0.25),
    )
    assert res["per_origin"], "no origin scored - fixture too small"
    for o in res["per_origin"]:
        assert set(o["recall_at_top_by_frac"]) == {"0.02", "0.25"}
        assert "c_index_ipcw" in o  # stored per origin (may be None on failure)
    agg = res["aggregate"]["c_index_ipcw"]
    assert set(agg) >= {"mean", "median", "sd", "n", "caveat"}
    assert "censoring" in agg["caveat"]  # the mandatory degenerate-weights caveat
    assert 0.0 < agg["mean"] < 1.0
