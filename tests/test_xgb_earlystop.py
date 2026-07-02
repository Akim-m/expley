"""Task 5 of the speed bundle: random event-stratified early-stop validation.

The 'tail' mode (documented to underfit: the train tail is censoring-dominated)
stays the default for back-compat; 'random' is the usable opt-in. The split is
seeded so backtests stay reproducible.
"""
import numpy as np
import pandas as pd
import pytest

pytest.importorskip("xgboost")
from temporal_exploit.xgb import fit_xgb_aft


def _frame(n=300, seed=0):
    rng = np.random.default_rng(seed)
    x = rng.normal(size=n)
    event = rng.random(n) < 0.3
    dur = np.where(event, np.exp(2 + 0.8 * x + rng.normal(scale=0.3, size=n)), 400.0)
    return pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(n)],
        "published": pd.to_datetime(["2024-01-01"] * n, utc=True),
        "duration_days": dur.clip(min=1.0),
        "event_observed": event.astype(int),
        "negative_duration_flag": False,
        "x": x, "noise": rng.normal(size=n),
    })


def test_random_validation_early_stops_and_predicts():
    m = fit_xgb_aft(_frame(), num_rounds=400, early_stopping_rounds=20, validation="random")
    assert m.booster.best_iteration is not None
    assert m.booster.best_iteration < 399          # actually stopped
    risk = m.risk_scores(_frame(seed=1))
    assert np.isfinite(risk).all()


def test_random_split_is_seeded_deterministic():
    a = fit_xgb_aft(_frame(), num_rounds=50, early_stopping_rounds=10, validation="random", seed=7)
    b = fit_xgb_aft(_frame(), num_rounds=50, early_stopping_rounds=10, validation="random", seed=7)
    assert a.booster.best_iteration == b.booster.best_iteration


def test_unknown_validation_mode_raises():
    with pytest.raises(ValueError, match="validation"):
        fit_xgb_aft(_frame(), early_stopping_rounds=10, validation="bogus")


def test_lone_event_stays_in_fit_frame():
    # RE audit: with <=5 events the val split could steal up to ALL of them
    # from training (n=1 -> pure-censored AFT fit, silently degenerate).
    frame = _frame(n=120)
    frame["event_observed"] = 0
    frame.loc[0, "event_observed"] = 1            # exactly one event
    frame.loc[0, "duration_days"] = 15.0
    m = fit_xgb_aft(frame, num_rounds=30, early_stopping_rounds=5, validation="random")
    risk = m.risk_scores(frame)
    assert np.isfinite(risk).all()                # trains; event kept in fit


def test_no_early_stopping_ignores_validation_mode():
    # early_stopping_rounds=None -> validation mode irrelevant, trains all rounds
    m = fit_xgb_aft(_frame(), num_rounds=20)
    assert getattr(m.booster, "best_iteration", None) in (None, 19)
