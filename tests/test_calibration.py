import numpy as np
import pandas as pd
import pytest

from temporal_exploit.calibration import (
    _wls_slope_intercept,
    apply_temperature,
    calibration_slope_intercept,
    fit_temperature,
)


def _miscalibrated(n=2000, seed=0):
    rng = np.random.default_rng(seed)
    p = rng.uniform(0.05, 0.6, n)  # true P(event by 90d)
    event = rng.random(n) < p
    durations = np.where(event, rng.uniform(1, 89, n), 200.0)  # censored at 200 if no event
    surv_over = ((1.0 - p) ** 3)[:, None]  # over-confident: CIF pushed too high
    return surv_over, durations, event


def test_temperature_recalibration_improves_brier():
    surv, dur, ev = _miscalibrated()
    cal, te = slice(0, 1000), slice(1000, None)
    a = fit_temperature(surv[cal], dur[cal], ev[cal], [90])
    y = (ev & (dur <= 90)).astype(float)[te]
    brier_before = np.mean((1.0 - surv[te, 0] - y) ** 2)
    brier_after = np.mean((1.0 - apply_temperature(surv[te], a)[:, 0] - y) ** 2)
    assert brier_after < brier_before  # the 1-param recalibration helped
    assert a < 0  # over-confident curve -> soften (exp(a) < 1)


def test_temperature_preserves_ranking():
    surv, dur, ev = _miscalibrated()
    a = fit_temperature(surv, dur, ev, [90])
    before = np.argsort(surv[:, 0])
    after = np.argsort(apply_temperature(surv, a)[:, 0])
    assert np.array_equal(before, after)  # monotone in S -> AUC/recall unchanged


def test_wls_slope_intercept_recovers_known_line():
    # perfectly calibrated bins: observed == predicted -> slope 1, intercept 0
    pred = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    w = np.array([100, 100, 100, 100, 100.0])
    s, b = _wls_slope_intercept(pred, pred, w)
    assert s == pytest.approx(1.0, abs=1e-9)
    assert b == pytest.approx(0.0, abs=1e-9)
    # under-confident by half: observed = 0.5*pred -> slope 0.5
    s2, b2 = _wls_slope_intercept(pred, 0.5 * pred, w)
    assert s2 == pytest.approx(0.5, abs=1e-9)
    assert b2 == pytest.approx(0.0, abs=1e-9)


def _calibrated_survival(n=6000, seed=0):
    """Synthetic where P(event by 90d) is known per subject (exponential), with
    light independent censoring -> KM-within-bin observed should match predicted."""
    rng = np.random.default_rng(seed)
    lam = rng.uniform(0.001, 0.02, n)  # per-day hazard
    t_event = rng.exponential(1.0 / lam)
    t_cens = rng.uniform(60, 400, n)
    dur = np.minimum(t_event, t_cens)
    ev = t_event <= t_cens
    pred_event_90 = 1.0 - np.exp(-lam * 90)  # true CIF at 90d
    frame = pd.DataFrame({"duration_days": dur, "event_observed": ev})
    return pred_event_90, frame


def test_calibration_slope_intercept_near_one_when_calibrated():
    pred, frame = _calibrated_survival()
    res = calibration_slope_intercept(pred, frame, horizon=90, n_boot=200, seed=0)
    # a well-calibrated model -> slope ~1, intercept ~0 (loose bands for KM noise)
    assert 0.75 <= res["slope"] <= 1.25
    assert abs(res["intercept"]) <= 0.1
    # bootstrap CI brackets the point estimate
    lo, hi = res["slope_ci95"]
    assert lo <= res["slope"] <= hi


def test_calibration_slope_detects_overconfidence():
    pred, frame = _calibrated_survival()
    # inflate predictions (over-confident) -> observed < predicted -> slope < 1
    pred_over = np.clip(pred * 2.5, 0, 0.999)
    res = calibration_slope_intercept(pred_over, frame, horizon=90, n_boot=100, seed=0)
    assert res["slope"] < 0.9
