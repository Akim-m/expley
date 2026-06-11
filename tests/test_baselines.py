import pandas as pd

from temporal_exploit.baselines import fit_kaplan_meier


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
