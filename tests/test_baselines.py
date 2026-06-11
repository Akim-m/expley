import pandas as pd
import pytest

from temporal_exploit.baselines import fit_cox_baseline, fit_kaplan_meier


def _labels():
    return pd.DataFrame(
        {
            "duration_days": [5, 10, 30, 60, 90],
            "event_observed": [True, True, False, True, False],
        }
    )


def test_kaplan_meier_returns_survival_function():
    fitter = fit_kaplan_meier(_labels())
    assert not fitter.survival_function_.empty
    assert fitter.survival_function_.columns.tolist() == ["first_weaponization"]


def test_cox_baseline_fits_numeric_feature():
    frame = pd.DataFrame(
        {
            "duration_days": [5, 10, 30, 60, 90, 120, 15, 45],
            "event_observed": [True, True, False, True, False, False, True, True],
            "cvss_v3_base": [9.8, 7.5, 5.3, 8.8, 4.3, 3.1, 9.1, 6.5],
        }
    )
    fitter = fit_cox_baseline(frame, ["cvss_v3_base"])
    assert "cvss_v3_base" in fitter.params_.index


def test_kaplan_meier_rejects_negative_duration():
    bad = pd.DataFrame(
        {"duration_days": [-5, 10, 30], "event_observed": [True, True, False]}
    )
    with pytest.raises(ValueError, match="negative"):
        fit_kaplan_meier(bad)


def test_cox_baseline_rejects_negative_duration():
    bad = pd.DataFrame(
        {
            "duration_days": [-5, 10, 30],
            "event_observed": [True, True, False],
            "cvss_v3_base": [9.8, 7.5, 5.3],
        }
    )
    with pytest.raises(ValueError, match="negative"):
        fit_cox_baseline(bad, ["cvss_v3_base"])
