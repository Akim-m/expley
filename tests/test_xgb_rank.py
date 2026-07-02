"""A2: LambdaRank top-push head — ranker on binary within-horizon labels."""
import numpy as np
import pandas as pd
import pytest

pytest.importorskip("xgboost")
from temporal_exploit.xgb import fit_xgb_rank


def _frame(n=400, seed=0):
    rng = np.random.default_rng(seed)
    x = rng.normal(size=n)
    # events concentrate on high-x rows, within 30d for half of them
    event = rng.random(n) < np.where(x > 0.5, 0.6, 0.05)
    dur = np.where(event, rng.integers(5, 60, size=n), 400).astype(float)
    return pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(n)],
        "published": pd.to_datetime(["2024-01-01"] * n, utc=True),
        "duration_days": dur,
        "event_observed": event.astype(int),
        "negative_duration_flag": False,
        "x": x, "noise": rng.normal(size=n),
    })


def test_ranker_learns_topk_signal():
    frame = _frame()
    m = fit_xgb_rank(frame, horizon=30, num_rounds=60, seed=0)
    risk = m.risk_scores(frame)
    assert np.isfinite(risk).all()
    # events within 30d must be enriched in the top decile vs base rate
    y = (frame["event_observed"].to_numpy(bool)) & (frame["duration_days"].to_numpy() <= 30)
    top = np.argsort(risk)[::-1][: len(frame) // 10]
    assert y[top].mean() > 2 * y.mean()


def test_ranker_survival_at_is_valid_pseudo_probability():
    frame = _frame()
    m = fit_xgb_rank(frame, horizon=30, num_rounds=30)
    surv = m.survival_at(frame, [30, 90])
    assert surv.shape == (len(frame), 2)
    assert ((surv > 0) & (surv < 1)).all()
    # monotone: higher risk -> lower pseudo-survival
    risk = m.risk_scores(frame)
    order = np.argsort(risk)
    assert (np.diff(surv[order, 0]) <= 1e-12).all()


def test_backtest_dispatch_accepts_xgb_rank():
    from temporal_exploit.backtest import rolling_origin_backtest

    rng = np.random.default_rng(3)
    n = 600
    pub = pd.to_datetime("2021-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 900, size=n), unit="D")
    corpus = pd.DataFrame({"cve_id": [f"CVE-{i}" for i in range(n)], "published": pub})
    x = rng.normal(size=n)
    is_event = rng.random(n) < (0.15 + 0.2 * (x > 0))
    events = pd.DataFrame({
        "cve_id": corpus["cve_id"][is_event],
        "date_added": (pub + pd.to_timedelta(rng.integers(5, 200, size=n), unit="D"))[is_event],
    })
    features = pd.DataFrame({"cve_id": corpus["cve_id"], "x": x})
    res = rolling_origin_backtest(
        corpus, {"kev": (events, "date_added")}, features,
        snapshot_date="2024-06-01", origins=["2022-07-01", "2023-01-01"],
        model="xgb_rank", label_set="in_wild", horizons=(30, 90),
        min_train=50, min_train_events=10, min_test=20,
    )
    assert res["per_origin"], "xgb_rank scored no origin"
    assert res["model"] == "xgb_rank"
