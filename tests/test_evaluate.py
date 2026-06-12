import pandas as pd

from temporal_exploit.evaluate import (
    cascade_order_stats,
    epss_reconciliation,
    event_rate_by_horizon,
    event_source_counts,
    event_source_dominance,
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


def test_event_source_dominance_flags_majority():
    labels = pd.DataFrame(
        {
            "event_observed": [True, True, True, False],
            "event_source": ["poc", "poc", "kev", "censored"],
        }
    )
    d = event_source_dominance(labels, threshold=0.5)
    assert d["dominant_source"] == "poc"
    assert d["dominant_share"] == round(2 / 3, 4)
    assert d["exceeds_threshold"] is True


def test_event_source_dominance_empty():
    labels = pd.DataFrame({"event_observed": [False], "event_source": ["censored"]})
    d = event_source_dominance(labels)
    assert d["dominant_source"] is None
    assert d["exceeds_threshold"] is False


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


def test_epss_reconciliation():
    labels = pd.DataFrame(
        {
            "cve_id": ["a", "b", "c", "d", "e"],
            "event_observed": [True, True, False, True, True],
            "duration_days": [5, 100, 100, 5, 5],
        }
    )
    epss = pd.DataFrame(
        {
            "cve_id": ["a", "b", "c", "d", "e"],
            "epss_at_publication": [0.9, 0.9, 0.1, 0.1, 0.9],
            "epss_at_publication_missing": [0, 0, 0, 0, 1],
        }
    )
    summary = epss_reconciliation(labels, epss, epss_threshold=0.5, horizon_days=30)
    q = summary.set_index(["high_epss", "weaponized_fast"])

    # e is missing -> excluded; 4 CVEs remain
    assert summary["count"].sum() == 4
    assert q.loc[(True, True), "count"] == 1   # a
    assert q.loc[(True, False), "count"] == 1  # b
    assert q.loc[(False, False), "count"] == 1  # c
    assert q.loc[(False, True), "count"] == 1  # d
    assert q.loc[(True, True), "pct"] == 25.0
