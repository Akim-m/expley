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


def test_cure_feature_cols_exclude_meta():
    from temporal_exploit.cure import fit_cure

    model = fit_cure(_synth_cure())
    assert model.feature_cols_ == ["feat_x"]
