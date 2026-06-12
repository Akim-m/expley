import pandas as pd

from temporal_exploit.epss_features import (
    build_epss_at_publication,
    epss_feature_provenance,
)


def _write_epss(path) -> str:
    epss_path = path / "epss_history.parquet"
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0001"],
            "date": pd.to_datetime(
                ["2023-12-30", "2024-01-02", "2024-02-01"], utc=True
            ),
            "epss": [0.10, 0.42, 0.55],
            "percentile": [0.30, 0.80, 0.90],
        }
    ).to_parquet(epss_path)
    return str(epss_path)


def _corpus() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": pd.to_datetime(["2024-01-01", "2024-01-01"], utc=True),
        }
    )


def test_takes_first_reading_on_or_after_publication(tmp_path) -> None:
    epss_path = _write_epss(tmp_path)
    features = build_epss_at_publication(_corpus(), epss_path)

    row = features.set_index("cve_id").loc["CVE-2024-0001"]
    assert row["epss_at_publication"] == 0.42
    assert row["epss_percentile_at_publication"] == 0.80
    assert row["epss_at_publication_missing"] == 0


def test_missing_when_no_epss_rows(tmp_path) -> None:
    epss_path = _write_epss(tmp_path)
    features = build_epss_at_publication(_corpus(), epss_path)

    row = features.set_index("cve_id").loc["CVE-2024-0002"]
    assert row["epss_at_publication"] == 0.0
    assert row["epss_percentile_at_publication"] == 0.0
    assert row["epss_at_publication_missing"] == 1


def test_one_row_per_corpus_cve(tmp_path) -> None:
    epss_path = _write_epss(tmp_path)
    features = build_epss_at_publication(_corpus(), epss_path)
    assert features["cve_id"].tolist() == ["CVE-2024-0001", "CVE-2024-0002"]


def test_snapshot_excludes_post_snapshot_readings(tmp_path) -> None:
    epss_path = _write_epss(tmp_path)
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published": pd.to_datetime(["2024-01-03"], utc=True),
        }
    )
    features = build_epss_at_publication(
        corpus, epss_path, snapshot_date="2024-01-15"
    )
    row = features.set_index("cve_id").loc["CVE-2024-0001"]
    # only the 2024-02-01 reading is on/after publication, but it is past the
    # snapshot, so the value is missing.
    assert row["epss_at_publication_missing"] == 1


def test_streaming_batches_match_single_batch(tmp_path) -> None:
    epss_path = _write_epss(tmp_path)
    single = build_epss_at_publication(_corpus(), epss_path)
    streamed = build_epss_at_publication(_corpus(), epss_path, batch_size=1)
    pd.testing.assert_frame_equal(single, streamed)


def test_provenance_covers_every_emitted_feature_family(tmp_path) -> None:
    epss_path = _write_epss(tmp_path)
    features = build_epss_at_publication(_corpus(), epss_path)
    provenance = epss_feature_provenance()

    assert set(provenance.columns) == {"feature_family", "source", "leakage_status", "notes"}
    assert set(provenance["leakage_status"]) == {"publication_time_safe"}

    families = set(provenance["feature_family"])
    for column in features.columns:
        if column == "cve_id":
            continue
        assert column in families
