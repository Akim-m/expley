import numpy as np

from temporal_exploit.calibration import apply_temperature, fit_temperature


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
