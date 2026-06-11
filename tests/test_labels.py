import pandas as pd

from temporal_exploit.labels import build_first_weaponization_labels, first_event_per_cve


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
            "event_date": pd.Timestamp("2024-01-05", tz="UTC"),
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


def test_build_first_weaponization_labels_uses_earliest_event() -> None:
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published": ["2024-01-01"],
        }
    )
    poc = pd.DataFrame({"cve_id": ["CVE-2024-0001"], "poc_first_seen": ["2024-01-15"]})
    kev = pd.DataFrame({"cve_id": ["CVE-2024-0001"], "kev_date_added": ["2024-01-20"]})

    labels = build_first_weaponization_labels(
        corpus=corpus,
        event_frames={"poc": (poc, "poc_first_seen"), "kev": (kev, "kev_date_added")},
        snapshot_date="2024-03-01",
    )

    row = labels.iloc[0]
    assert bool(row["event_observed"]) is True
    assert row["event_source"] == "poc"
    assert row["event_date"] == pd.Timestamp("2024-01-15", tz="UTC")
    assert row["duration_days"] == 14


def test_build_first_weaponization_labels_censors_missing_events() -> None:
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0002"],
            "published": ["2024-02-01"],
        }
    )

    labels = build_first_weaponization_labels(
        corpus=corpus,
        event_frames={},
        snapshot_date="2024-03-01",
    )

    row = labels.iloc[0]
    assert bool(row["event_observed"]) is False
    assert row["event_source"] == "censored"
    assert pd.isna(row["event_date"])
    assert row["duration_days"] == 29


def test_build_first_weaponization_labels_flags_negative_durations() -> None:
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0003"],
            "published": ["2024-02-01"],
        }
    )
    poc = pd.DataFrame({"cve_id": ["CVE-2024-0003"], "poc_first_seen": ["2024-01-25"]})

    labels = build_first_weaponization_labels(
        corpus=corpus,
        event_frames={"poc": (poc, "poc_first_seen")},
        snapshot_date="2024-03-01",
    )

    row = labels.iloc[0]
    assert row["duration_days"] == -7
    assert bool(row["negative_duration_flag"]) is True


def test_labels_handle_tz_aware_dates():
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
        }
    )
    poc = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": pd.to_datetime(["2024-01-11"], utc=True),
        }
    )
    labels = build_first_weaponization_labels(
        corpus, {"poc": (poc, "poc_first_seen")}, snapshot_date="2024-03-01"
    )
    observed = labels.loc[labels["cve_id"] == "CVE-2024-0001"].iloc[0]
    censored = labels.loc[labels["cve_id"] == "CVE-2024-0002"].iloc[0]
    assert observed["duration_days"] == 10
    assert censored["event_source"] == "censored"
    assert censored["duration_days"] == 29
