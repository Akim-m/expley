"""Tests for the causal-inference helpers."""
import numpy as np
import pandas as pd
import pytest

from temporal_exploit.causal import estimate_effect, evalue, hr_to_rr


def test_evalue_null_when_ci_crosses_one():
    ev = evalue(1.1, 0.9, 1.3)
    assert ev["ci_bound"] == 1.0          # CI crosses null -> nothing to explain
    assert ev["point"] > 1.0


def test_evalue_symmetric_in_protective_direction():
    # HR and 1/HR must give the same E-value (protective vs harmful symmetry)
    a = evalue(2.0, 1.5, 2.6)["point"]
    b = evalue(0.5, 0.38, 0.66)["point"]
    assert a == pytest.approx(b, rel=1e-6)


def test_hr_to_rr_monotone_and_identity_at_one():
    assert hr_to_rr(1.0) == pytest.approx(1.0, rel=1e-6)
    assert hr_to_rr(2.0) > 1.0
    assert hr_to_rr(0.5) < 1.0


def _synthetic(n=4000, seed=0):
    """Treatment raises the hazard (shorter durations) AND is confounded by C."""
    rng = np.random.default_rng(seed)
    c = rng.normal(size=n)                       # confounder
    p = 1 / (1 + np.exp(-c))                      # C drives treatment
    t = (rng.uniform(size=n) < p).astype(int)
    # higher hazard for treated and for high-C -> shorter time
    base = rng.exponential(scale=np.exp(-(0.7 * t + 0.5 * c)))
    dur = np.clip(base * 100, 0.5, None)
    obs = (dur < 80).astype(int)                  # administrative censoring
    return pd.DataFrame({"treat": t, "C": c, "duration_days": dur, "event_observed": obs})


def test_estimate_effect_recovers_positive_effect_and_reports_blocks():
    df = _synthetic()
    out = estimate_effect(df, "treat", ["C"])
    # treatment genuinely accelerates -> all three HRs > 1
    assert out["crude_hr"]["hr"] > 1.0
    assert out["adjusted_hr"]["hr"] > 1.0
    assert out["ipw_hr"]["hr"] > 1.0
    # adjusting for the confounder should move the estimate (crude != adjusted)
    assert out["crude_hr"]["hr"] != out["adjusted_hr"]["hr"]
    assert set(out["ipw_hr"]["overlap"]) == {
        "ps_treated_p05_p50_p95", "ps_control_p05_p50_p95", "weight_max",
    }
    assert out["n"] == len(df)
