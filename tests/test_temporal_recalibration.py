"""Temporal recalibration (Booth, Riley, Rutherford 2020, IJE 49(4):1316): re-estimate
ONLY the Cox baseline hazard on a recent calendar window, keeping the covariate effects,
to repair calibration drift under a non-stationary baseline hazard.

The defining property is rank-preservation: risk = exp(beta.x) uses the unchanged betas,
so the per-subject risk ORDER (hence AUC / c-index) is identical -- only the absolute
survival probabilities move. That invariant is the first test.
"""
import numpy as np
import pandas as pd

from temporal_exploit.modeling import fit_cox
from temporal_exploit.temporal_recalibration import temporal_recalibrate


def _synthetic(n, seed):
    rng = np.random.default_rng(seed)
    x = rng.normal(size=n)
    # higher x -> earlier event (monotone), all observed
    dur = (rng.exponential(scale=np.exp(-0.6 * x)) + 0.05) * 100.0
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-{seed}-{i}" for i in range(n)],
            "published": pd.Timestamp("2020-01-01", tz="UTC"),
            "duration_days": dur,
            "event_observed": True,
            "negative_duration_flag": False,
            "x": x,
        }
    )


def test_recalibration_preserves_ranking():
    frame = _synthetic(500, 0)
    cox = fit_cox(frame)
    recent = _synthetic(300, 1)  # a fresh calendar window with its own baseline
    recal = temporal_recalibrate(cox, recent)

    X = frame[cox.feature_cols_].astype(float)
    base = cox.predict_partial_hazard(X).to_numpy().ravel()
    new = np.asarray(recal.risk_scores(X)).ravel()
    # re-estimating the baseline cannot reorder subjects -> identical risk ranking
    assert np.array_equal(np.argsort(base), np.argsort(new))


def _cohort(x, scale, seed):
    rng = np.random.default_rng(seed)
    dur = rng.exponential(scale=scale, size=len(x)) * np.exp(-0.6 * x)
    return pd.DataFrame(
        {
            "cve_id": [f"C{seed}-{i}" for i in range(len(x))],
            "published": pd.Timestamp("2020-01-01", tz="UTC"),
            "duration_days": dur,
            "event_observed": True,
            "negative_duration_flag": False,
            "x": x,
        }
    )


def test_recalibration_fixes_calibration_under_baseline_shift():
    # The model is fit on a SLOW era (scale 500) but deployed on a FAST recent era
    # (scale 50). On a HELD-OUT recent cohort the stale baseline under-predicts events;
    # recalibrating on a recent window moves the predicted event rate toward the truth.
    from temporal_exploit.modeling import survival_at

    rng = np.random.default_rng(3)
    old = _cohort(rng.normal(size=400), scale=500.0, seed=20)
    xr = rng.normal(size=400)
    recent_fit = _cohort(xr[:200], scale=50.0, seed=21)
    recent_eval = _cohort(xr[200:], scale=50.0, seed=22)

    cox = fit_cox(old)
    h = 60
    truth = float((recent_eval["duration_days"].to_numpy() <= h).mean())
    Xe = recent_eval[cox.feature_cols_].astype(float)

    orig_event = float((1.0 - survival_at(cox, Xe, [h], "cox")[:, 0]).mean())
    recal = temporal_recalibrate(cox, recent_fit)
    recal_event = float((1.0 - recal.survival_at(Xe, [h])[:, 0]).mean())

    assert abs(recal_event - truth) < abs(orig_event - truth)


def test_survival_at_finite_under_partial_hazard_overflow():
    # An extreme covariate row overflows exp(beta.(x - mean)) to +inf. At a horizon
    # before the first recent event time H0=0, and inf * 0 would give NaN -- silently
    # poisoning downstream Brier/calibration. The correct value is S=1.0.
    frame = _cohort(np.random.default_rng(0).normal(size=300), scale=50.0, seed=30)
    cox = fit_cox(frame)
    recal = temporal_recalibrate(cox, frame)
    X = pd.DataFrame({"x": [5000.0]})  # partial hazard overflows to +inf
    S = recal.survival_at(X, [0.0, float(recal._times[0]) * 0.5])
    assert np.isfinite(S).all()
    assert np.allclose(S, 1.0)  # before the first event time, S=1 regardless of risk
