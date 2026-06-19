import numpy as np
import pandas as pd


def _synth_cure(n=4000, seed=0):
    """Synthetic mixture-cure data: a logistic susceptible-probability, Weibull
    latency for susceptibles, administrative censoring at 365 days."""
    rng = np.random.default_rng(seed)
    x = rng.normal(size=n)
    p_sus = 1.0 / (1.0 + np.exp(-(0.5 + 1.0 * x)))  # P(susceptible)
    susceptible = rng.random(n) < p_sus
    t = rng.weibull(1.3, size=n) * 50.0  # latency for susceptibles (mean ~46d)
    censor = 365.0
    dur = np.where(susceptible, np.minimum(t, censor), censor)
    obs = susceptible & (t <= censor)
    return pd.DataFrame(
        {
            "cve_id": np.arange(n),
            "published": pd.Timestamp("2020-01-01", tz="UTC"),
            "duration_days": dur.astype(float),
            "event_observed": obs,
            "negative_duration_flag": False,
            "feat_x": x,
        }
    )


def test_cure_recovers_fraction_and_plateaus():
    from temporal_exploit.cure import fit_cure

    model = fit_cure(_synth_cure())
    # at the population mean (x=0), susceptible prob ~ sigmoid(0.5) ~ 0.62,
    # so the cure fraction (never-event) is ~0.38.
    Xmean = pd.DataFrame({"feat_x": [0.0]})
    cure = float(model.cure_fraction(Xmean)[0])
    assert 0.25 < cure < 0.55

    surv = model.survival_at(Xmean, [10, 100, 100_000])
    assert surv.shape == (1, 3)
    assert surv[0, 0] > surv[0, 1] > surv[0, 2]   # population S(t) decreasing
    assert surv[0, 2] > 0.20                       # plateaus at the cured mass, not 0
    assert 0.0 < surv[0, 2] < 1.0


def test_cure_risk_scores_rank_susceptibles_higher():
    from temporal_exploit.cure import fit_cure

    model = fit_cure(_synth_cure())
    # higher feat_x -> higher susceptible prob (gamma>0) -> higher risk score
    X = pd.DataFrame({"feat_x": [-2.0, 2.0]})
    risk = model.risk_scores(X)
    assert risk.shape == (2,)
    assert risk[1] > risk[0]
    assert np.all((risk >= 0) & (risk <= 1))


def test_cure_analytic_gradient_matches_finite_difference():
    from scipy.optimize import approx_fprime

    from temporal_exploit.cure import _objective

    rng = np.random.default_rng(3)
    n, p = 200, 2
    Xs = rng.normal(size=(n, p))
    logt = np.log(rng.uniform(1.0, 300.0, n))
    observed = rng.random(n) < 0.4
    ridge = 0.7
    theta = rng.normal(scale=0.3, size=2 * p + 3)

    _, grad = _objective(theta, Xs, logt, observed, ridge)
    fd = approx_fprime(theta, lambda th: _objective(th, Xs, logt, observed, ridge)[0], 1e-6)
    assert np.allclose(grad, fd, rtol=1e-4, atol=1e-4)


def test_cure_gradient_correct_in_clipped_region(monkeypatch):
    # exercise the z >= _Z_MAX branch (where ez saturates): the gradient must be
    # the exact gradient of the *clipped* NLL (ez-derivative zeroed), not use the
    # saturated ez. Lower _Z_MAX so the clipped ez stays finite/FD-testable.
    from scipy.optimize import approx_fprime

    from temporal_exploit import cure as cure_mod

    monkeypatch.setattr(cure_mod, "_Z_MAX", 5.0)
    rng = np.random.default_rng(11)
    n, p = 120, 2
    Xs = rng.normal(scale=0.2, size=(n, p))
    logt = rng.uniform(1.0, 2.0, n)
    observed = rng.random(n) < 0.5
    ridge = 0.5
    theta = np.zeros(2 * p + 3)
    theta[1 + p] = -2.0   # a0 -> log_scale ~ -2 -> u ~ 3-4
    theta[-1] = 1.0       # log_k -> k ~ 2.72 -> k*u ~ 8-11 >> 5 (all clipped)
    k = np.exp(theta[-1])
    s = theta[1 + p] + Xs @ theta[2 + p : 2 + 2 * p]
    assert (k * (logt - s) >= 5.0).all()  # the clipped branch is actually hit

    _, grad = cure_mod._objective(theta, Xs, logt, observed, ridge)
    fd = approx_fprime(
        theta, lambda th: cure_mod._objective(th, Xs, logt, observed, ridge)[0], 1e-7
    )
    assert np.allclose(grad, fd, rtol=1e-3, atol=1e-3)


def test_cure_feature_cols_exclude_meta():
    from temporal_exploit.cure import fit_cure

    model = fit_cure(_synth_cure())
    assert model.feature_cols_ == ["feat_x"]


def test_cure_loglogistic_gradient_matches_finite_difference():
    from scipy.optimize import approx_fprime

    from temporal_exploit.cure import _objective

    rng = np.random.default_rng(5)
    n, p = 200, 2
    Xs = rng.normal(size=(n, p))
    logt = np.log(rng.uniform(1.0, 300.0, n))
    observed = rng.random(n) < 0.4
    ridge = 0.7
    theta = rng.normal(scale=0.3, size=2 * p + 3)
    _, grad = _objective(theta, Xs, logt, observed, ridge, latency="loglogistic")
    fd = approx_fprime(
        theta, lambda th: _objective(th, Xs, logt, observed, ridge, latency="loglogistic")[0], 1e-6
    )
    assert np.allclose(grad, fd, rtol=1e-4, atol=1e-4)


def test_cure_auto_selects_lower_aic_latency():
    from temporal_exploit.cure import LATENCY_FAMILIES, fit_cure

    frame = _synth_cure(n=2500)
    aics = {fam: fit_cure(frame, latency=fam).aic_ for fam in LATENCY_FAMILIES}
    auto = fit_cure(frame, latency="auto")
    assert auto.latency_ in LATENCY_FAMILIES and auto.aic_ is not None
    assert auto.latency_ == min(aics, key=aics.get)


def test_cure_recalibration_is_monotone():
    from temporal_exploit.cure import fit_cure

    frame = _synth_cure()
    model = fit_cure(frame, latency="weibull")
    sub = frame.head(200)
    before = model.survival_at(sub, [30])[:, 0]
    model.recalibrate(frame, [30, 100])
    after = model.survival_at(sub, [30])[:, 0]
    order = np.argsort(before)
    assert np.all(np.diff(after[order]) >= -1e-9)   # monotone in the original prediction
    assert np.all((after >= 0.0) & (after <= 1.0))
