import pandas as pd

from temporal_exploit.evaluate import event_rate_by_horizon


def _labels():
    return pd.DataFrame(
        {
            "cve_id": ["a", "b", "c", "d"],
            "event_observed": [True, True, False, False],
            "duration_days": [5, 45, 100, 200],
            "event_source": ["poc", "kev", "censored", "censored"],
        }
    )


def test_event_rate_by_horizon():
    rates = event_rate_by_horizon(_labels(), horizons=[7, 30, 90, 180])
    assert rates["horizon_days"].tolist() == [7, 30, 90, 180]
    assert rates["observed_events"].tolist() == [1, 1, 2, 2]
    assert rates["n"].tolist() == [4, 4, 4, 4]
    assert rates["observed_event_rate"].tolist() == [0.25, 0.25, 0.5, 0.5]
