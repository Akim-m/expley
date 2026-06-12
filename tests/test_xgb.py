import numpy as np
import pandas as pd
import pytest

pytest.importorskip("xgboost")

from temporal_exploit.modeling import (  # noqa: E402
    evaluate_survival,
    prepare_modeling_frame,
    survival_at,
    time_split_frame,
)
from temporal_exploit.xgb import fit_xgb_aft  # noqa: E402


def _synthetic(n=300, seed=0):
    rng = np.random.default_rng(seed)
    cvss = rng.uniform(2.0, 10.0, n)
    true_time = np.clip(200.0 - 15.0 * cvss + rng.normal(0, 20, n), 1.0, None)
    censor = rng.uniform(30.0, 250.0, n)
    duration = np.minimum(true_time, censor)
    observed = true_time <= censor
    published = pd.to_datetime("2023-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 700, n), unit="D"
    )
    labels = pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{i:05d}" for i in range(n)],
            "published": published,
            "duration_days": duration,
            "event_observed": observed,
            "negative_duration_flag": False,
        }
    )
    features = pd.DataFrame(
        {
            "cve_id": labels["cve_id"],
            "published": published,
            "cvss_v3_base": cvss,
            "vendor_count": rng.integers(1, 6, n),
        }
    )
    return prepare_modeling_frame(labels, features)


def test_fit_xgb_aft_and_survival_curve_properties():
    frame = _synthetic()
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_xgb_aft(train, num_rounds=50)

    assert model.feature_cols_ == ["cvss_v3_base", "vendor_count"]
    X = test[model.feature_cols_].astype(float)
    surv = survival_at(model, X, [7, 30, 90, 180], "xgb")

    assert surv.shape == (len(test), 4)
    assert ((surv >= 0) & (surv <= 1)).all()
    assert (np.diff(surv, axis=1) <= 1e-12).all()  # S(t) non-increasing in t


def test_default_fit_does_not_early_stop():
    # Early stopping must be opt-in: the time-tail validation split is mostly
    # censored (shortest follow-up before the cutoff), so aft-nloglik on it
    # rewards underfitting — on the real corpus it stopped at iter 57/500 and
    # cost 7 c-index points (0.607 -> 0.537).
    frame = _synthetic(n=400)
    model = fit_xgb_aft(frame, num_rounds=60)
    assert getattr(model.booster, "best_iteration", None) is None
    assert model.booster.num_boosted_rounds() == 60


def test_early_stopping_uses_validation_tail():
    frame = _synthetic(n=400)
    model = fit_xgb_aft(frame, num_rounds=300, early_stopping_rounds=20)
    assert getattr(model.booster, "best_iteration", None) is not None
    assert model.booster.best_iteration < 300
    X = frame[model.feature_cols_].astype(float)
    surv = survival_at(model, X, [30], "xgb")
    assert ((surv >= 0) & (surv <= 1)).all()


def test_risk_scores_stay_finite_when_aft_prediction_under_or_overflows():
    # On heavily censored frames AFT predicted times exp(mu) can hit 0 or inf;
    # log() must not produce infinite risk scores (sksurv rejects them).
    import xgboost  # noqa: F401  (DMatrix used inside _mu)

    from temporal_exploit.xgb import XgbAftModel

    class ExtremeBooster:
        best_iteration = None

        def predict(self, dmatrix, iteration_range=None):
            return np.array([0.0, np.inf, 100.0])

    model = XgbAftModel(ExtremeBooster(), ["a"], sigma=1.0, distribution="normal")
    X = pd.DataFrame({"a": [1.0, 2.0, 3.0]})
    risk = model.risk_scores(X)
    assert np.isfinite(risk).all()
    surv = model.survival_at(X, [30])
    assert np.isfinite(surv).all()
    assert ((surv >= 0) & (surv <= 1)).all()


def test_evaluate_survival_xgb():
    frame = _synthetic()
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_xgb_aft(train, num_rounds=50)
    res = evaluate_survival(model, train, test, horizons=(7, 30, 90), kind="xgb")

    assert res["kind"] == "xgb"
    assert 0.0 <= res["c_index_ipcw"] <= 1.0
    # cvss drives the synthetic times, so the model should beat coin-flip
    assert res["c_index_ipcw"] > 0.6
    for v in res["brier"].values():
        assert 0.0 <= v <= 1.0
