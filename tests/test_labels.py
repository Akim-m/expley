import pandas as pd

from temporal_exploit.labels import first_event_per_cve


def test_first_event_per_cve_takes_earliest_valid_date() -> None:
    frame = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002"],
            "poc_first_seen": ["2024-01-10", "2024-01-05", None],
        }
    )

    events = first_event_per_cve(frame, date_col="poc_first_seen", source="poc")

    assert events.to_dict("records") == [
        {
            "cve_id": "CVE-2024-0001",
            "event_date": pd.Timestamp("2024-01-05"),
            "event_source": "poc",
        }
    ]


def test_first_event_per_cve_drops_invalid_dates() -> None:
    frame = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": ["not-a-date"],
        }
    )

    events = first_event_per_cve(frame, date_col="poc_first_seen", source="poc")

    assert events.empty
