import numpy as np
import pandas as pd
import pytest

from temporal_exploit.landmark import (
    build_epss_at_landmark,
    build_landmark_features,
    landmark_feature_provenance,
    restart_clock,
)


def _corpus():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "published": pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01"], utc=True),
        }
    )


def _tooling_frames():
    poc = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002"],
            "poc_first_seen": pd.to_datetime(
                ["2024-01-04", "2024-01-20", "2024-03-10"], utc=True
            ),
        }
    )
    msf = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            # exactly at the L=7 landmark: must count (<=)
            "metasploit_first_seen": pd.to_datetime(["2024-01-08"], utc=True),
        }
    )
    nuclei = pd.DataFrame(
        {
            "cve_id": pd.Series(dtype=str),
            "nuclei_first_seen": pd.Series(dtype="datetime64[ns, UTC]"),
        }
    )
    return {
        "poc": (poc, "poc_first_seen"),
        "metasploit": (msf, "metasploit_first_seen"),
        "nuclei": (nuclei, "nuclei_first_seen"),
    }


def test_build_landmark_features_l7():
    feats = build_landmark_features(_corpus(), _tooling_frames(), landmark_days=7)
    feats = feats.set_index("cve_id")

    # CVE-1: poc at day 3 (in), second poc at day 19 (out), msf exactly at day 7 (in)
    row = feats.loc["CVE-2024-0001"]
    assert row["poc_by_landmark"] == 1
    assert row["poc_count_by_landmark"] == 1
    assert row["poc_lag_days"] == 3.0
    assert row["metasploit_by_landmark"] == 1
    assert row["metasploit_lag_days"] == 7.0
    assert row["nuclei_by_landmark"] == 0

    # CVE-2: poc at day 38 — outside the landmark; lag fill is L+1 (later
    # than any attainable in-window lag, monotone with "arrived later")
    row = feats.loc["CVE-2024-0002"]
    assert row["poc_by_landmark"] == 0
    assert row["poc_count_by_landmark"] == 0
    assert row["poc_lag_days"] == 8.0

    # CVE-3: no tooling at all
    row = feats.loc["CVE-2024-0003"]
    assert row["poc_by_landmark"] == 0
    assert row["metasploit_by_landmark"] == 0


def test_build_landmark_features_wider_landmark_includes_more():
    feats = build_landmark_features(_corpus(), _tooling_frames(), landmark_days=60)
    feats = feats.set_index("cve_id")
    assert feats.loc["CVE-2024-0001", "poc_count_by_landmark"] == 2
    assert feats.loc["CVE-2024-0002", "poc_by_landmark"] == 1
    assert feats.loc["CVE-2024-0002", "poc_lag_days"] == 38.0


def test_pre_publication_tooling_lag_stays_negative_and_distinct():
    # A PoC seen before publication must not collide with the no-signal fill
    corpus = _corpus().iloc[:1]
    poc = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": pd.to_datetime(["2023-12-26"], utc=True),  # 6d pre-pub
        }
    )
    feats = build_landmark_features(corpus, {"poc": (poc, "poc_first_seen")}, landmark_days=7)
    assert feats.loc[0, "poc_by_landmark"] == 1
    assert feats.loc[0, "poc_lag_days"] == -6.0


def test_duplicate_cve_ids_raise():
    corpus = pd.concat([_corpus(), _corpus().iloc[:1]], ignore_index=True)
    with pytest.raises(ValueError, match="duplicate"):
        build_landmark_features(corpus, _tooling_frames(), landmark_days=7)


def test_missing_published_raises():
    corpus = _corpus()
    corpus.loc[0, "published"] = pd.NaT
    with pytest.raises(ValueError, match="published"):
        build_landmark_features(corpus, _tooling_frames(), landmark_days=7)


def test_restart_clock_rejects_negative_landmark():
    labels = pd.DataFrame(
        {
            "cve_id": ["A"],
            "published": pd.to_datetime(["2024-01-01"], utc=True),
            "duration_days": [10],
            "event_observed": [True],
            "negative_duration_flag": [False],
        }
    )
    with pytest.raises(ValueError, match="landmark_days"):
        restart_clock(labels, landmark_days=-5)


def test_restart_clock_filters_risk_set_and_shifts_durations():
    labels = pd.DataFrame(
        {
            "cve_id": ["A", "B", "C", "D"],
            "published": pd.to_datetime(["2024-01-01"] * 4, utc=True),
            "duration_days": [10, 40, 100, -3],
            "event_observed": [True, True, False, True],
            "negative_duration_flag": [False, False, False, True],
        }
    )
    out = restart_clock(labels, landmark_days=30)

    # A (event at day 10 <= L) and D (negative duration) leave the risk set
    assert sorted(out["cve_id"]) == ["B", "C"]
    assert out.set_index("cve_id").loc["B", "duration_days"] == 10
    assert out.set_index("cve_id").loc["C", "duration_days"] == 70
    assert bool(out.set_index("cve_id").loc["B", "event_observed"]) is True
    assert bool(out.set_index("cve_id").loc["C", "event_observed"]) is False


def test_restart_clock_boundary_event_at_landmark_excluded():
    labels = pd.DataFrame(
        {
            "cve_id": ["A"],
            "published": pd.to_datetime(["2024-01-01"], utc=True),
            "duration_days": [30],
            "event_observed": [True],
            "negative_duration_flag": [False],
        }
    )
    assert restart_clock(labels, landmark_days=30).empty


def test_build_epss_at_landmark_takes_last_reading_in_window(tmp_path):
    corpus = _corpus().iloc[:2]
    history = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"] * 3 + ["CVE-2024-0002"],
            "date": pd.to_datetime(
                ["2024-01-01", "2024-01-05", "2024-01-20", "2024-02-20"], utc=True
            ),
            "epss": [0.1, 0.4, 0.9, 0.5],
            "percentile": [0.5, 0.7, 0.99, 0.8],
        }
    )
    path = tmp_path / "epss.parquet"
    history.to_parquet(path)

    out = build_epss_at_landmark(corpus, str(path), landmark_days=7)
    out = out.set_index("cve_id")

    # CVE-1: readings at day 0 and 4 are in [published, published+7]; last wins
    assert out.loc["CVE-2024-0001", "epss_at_landmark"] == pytest.approx(0.4)
    assert out.loc["CVE-2024-0001", "epss_at_landmark_missing"] == 0
    # CVE-2: only reading is day 19 — outside the window
    assert out.loc["CVE-2024-0002", "epss_at_landmark_missing"] == 1
    assert out.loc["CVE-2024-0002", "epss_at_landmark"] == 0.0


def test_provenance_rows_cover_every_feature_family():
    prov = landmark_feature_provenance(landmark_days=30)
    assert (prov["leakage_status"] == "landmark_safe").all()
    families = set(prov["feature_family"])
    for fam in ("poc_by_landmark", "metasploit_by_landmark", "nuclei_by_landmark",
                "poc_count_by_landmark", "poc_lag_days", "epss_at_landmark"):
        assert any(fam.rstrip("*").startswith(f.rstrip("*")) or f.startswith(fam)
                   for f in families), fam


def test_landmark_features_handle_ndarray_free_frames():
    # numpy-int durations and tz-aware datetimes must survive the round trip
    feats = build_landmark_features(_corpus(), _tooling_frames(), landmark_days=7)
    assert feats["poc_by_landmark"].dtype.kind in "iu"
    assert feats["poc_lag_days"].dtype == np.float64
