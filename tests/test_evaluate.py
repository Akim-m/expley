import pandas as pd

from temporal_exploit.evaluate import (
    cascade_order_stats,
    event_rate_by_horizon,
    event_source_counts,
)


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


def test_event_source_counts():
    counts = event_source_counts(_labels())
    by_source = counts.set_index("event_source")
    assert by_source.loc["censored", "count"] == 2
    assert by_source.loc["censored", "pct"] == 50.0
    assert by_source.loc["poc", "count"] == 1


def _per_signal():
    def ts(values):
        return pd.to_datetime(values, utc=True)

    return pd.DataFrame(
        {
            "cve_id": ["a", "b", "c"],
            "poc_observed": [True, True, False],
            "poc_event_date": ts(["2024-01-01", "2024-02-01", None]),
            "metasploit_observed": [True, True, False],
            "metasploit_event_date": ts(["2024-01-10", "2024-02-05", None]),
            "nuclei_observed": [False, False, False],
            "nuclei_event_date": ts([None, None, None]),
            "kev_observed": [True, False, False],
            "kev_event_date": ts(["2024-03-01", None, None]),
        }
    )


def test_cascade_order_stats():
    stats = cascade_order_stats(_per_signal())
    by_pair = stats.set_index(["from_stage", "to_stage"])

    pm = by_pair.loc[("poc", "metasploit")]
    assert pm["n_both"] == 2
    assert pm["n_a_before_b"] == 2
    assert pm["pct_a_before_b"] == 100.0

    mn = by_pair.loc[("metasploit", "nuclei")]
    assert mn["n_both"] == 0
    assert mn["pct_a_before_b"] == 0.0

    assert stats["from_stage"].tolist() == ["poc", "metasploit", "nuclei"]
    assert stats["to_stage"].tolist() == ["metasploit", "nuclei", "kev"]
