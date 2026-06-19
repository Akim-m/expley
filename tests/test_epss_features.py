import pandas as pd
import pyarrow.parquet as pq

from temporal_exploit.epss_features import (
    _epss_row_groups,
    _iter_epss_batches,
    _ns,
    build_epss_at_publication,
    epss_feature_columns,
    epss_feature_provenance,
)


def test_epss_feature_columns_selects_epss_prefixed():
    cols = [
        "cve_id", "published", "cvss_v3_base",
        "epss_at_publication", "epss_percentile_at_publication",
        "epss_at_publication_missing", "epss_at_landmark",
    ]
    assert epss_feature_columns(cols) == [
        "epss_at_publication", "epss_percentile_at_publication",
        "epss_at_publication_missing", "epss_at_landmark",
    ]
    assert epss_feature_columns(["cve_id", "cvss_v3_base"]) == []
from tests.fixtures.tiny_parquets import write_epss_row_groups


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


def test_nan_percentile_filled_to_zero(tmp_path):
    # a reading with valid epss but NaN percentile must not leak NaN into features
    epss_path = tmp_path / "epss_history.parquet"
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "date": pd.to_datetime(["2024-01-05"], utc=True),
            "epss": [0.42],
            "percentile": [float("nan")],
        }
    ).to_parquet(epss_path)
    corpus = pd.DataFrame(
        {"cve_id": ["CVE-2024-0001"], "published": pd.to_datetime(["2024-01-01"], utc=True)}
    )
    feat = build_epss_at_publication(corpus, str(epss_path)).set_index("cve_id")
    assert feat.loc["CVE-2024-0001", "epss_at_publication"] == 0.42
    assert feat.loc["CVE-2024-0001", "epss_percentile_at_publication"] == 0.0
    assert feat.loc["CVE-2024-0001", "epss_at_publication_missing"] == 0


# --- date-based row-group skipping (the 375M-row file is 1 row group per date) ---


def test_epss_row_groups_fixture_is_one_group_per_date(tmp_path):
    p = write_epss_row_groups(
        tmp_path,
        {
            "2024-01-01": [("CVE-2024-0001", 0.1, 0.3)],
            "2024-02-01": [("CVE-2024-0001", 0.4, 0.8)],
            "2024-03-01": [("CVE-2024-0001", 0.5, 0.9)],
        },
    )
    assert pq.ParquetFile(p).metadata.num_row_groups == 3


def test_epss_row_groups_selects_only_in_range(tmp_path):
    p = write_epss_row_groups(
        tmp_path,
        {
            "2024-01-01": [("CVE-2024-0001", 0.1, 0.3)],
            "2024-02-01": [("CVE-2024-0001", 0.4, 0.8)],
            "2024-03-01": [("CVE-2024-0001", 0.5, 0.9)],
        },
    )
    pf = pq.ParquetFile(p)
    assert _epss_row_groups(pf, None, None) == [0, 1, 2]
    # upper bound drops the 2024-03-01 group
    assert _epss_row_groups(pf, None, _ns(["2024-02-15"])[0]) == [0, 1]
    # lower bound drops the 2024-01-01 group
    assert _epss_row_groups(pf, _ns(["2024-01-15"])[0], None) == [1, 2]
    # both bounds -> only the middle group
    assert _epss_row_groups(pf, _ns(["2024-01-15"])[0], _ns(["2024-02-15"])[0]) == [1]
    # boundary dates are inclusive
    assert _epss_row_groups(pf, _ns(["2024-02-01"])[0], _ns(["2024-02-01"])[0]) == [1]


def test_iter_epss_batches_skips_out_of_range_row_groups(tmp_path):
    p = write_epss_row_groups(
        tmp_path,
        {
            "2024-01-01": [("CVE-2024-0001", 0.1, 0.3)],
            "2024-02-01": [("CVE-2024-0002", 0.4, 0.8)],
            "2024-03-01": [("CVE-2024-0003", 0.5, 0.9)],
        },
    )
    seen = []
    for batch in _iter_epss_batches(p, None, _ns(["2024-02-15"])[0], batch_size=1024):
        seen.extend(batch.column("cve_id").to_pylist())
    assert seen == ["CVE-2024-0001", "CVE-2024-0002"]  # 2024-03-01 group never decoded


def test_build_epss_at_publication_correct_when_late_row_group_skipped(tmp_path):
    p = write_epss_row_groups(
        tmp_path,
        {
            "2024-01-01": [("CVE-2024-0001", 0.10, 0.30)],
            "2024-02-01": [("CVE-2024-0001", 0.40, 0.80), ("CVE-2024-0002", 0.20, 0.50)],
            "2024-03-01": [("CVE-2024-0001", 0.55, 0.90), ("CVE-2024-0002", 0.60, 0.95)],
        },
    )
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": pd.to_datetime(["2024-01-15", "2024-01-15"], utc=True),
        }
    )
    # snapshot before the 2024-03-01 group -> that group is skipped by the pushdown,
    # but the answer (first reading on/after publication within snapshot) is unchanged.
    feat = build_epss_at_publication(corpus, p, snapshot_date="2024-02-15").set_index("cve_id")
    assert feat.loc["CVE-2024-0001", "epss_at_publication"] == 0.40
    assert feat.loc["CVE-2024-0002", "epss_at_publication"] == 0.20
    assert feat.loc["CVE-2024-0001", "epss_at_publication_missing"] == 0


def test_snapshot_before_all_row_groups_decodes_nothing(tmp_path):
    # a snapshot earlier than the whole file -> no row group can hold an eligible
    # reading, so selection is empty and every CVE is missing (zero decode).
    p = write_epss_row_groups(
        tmp_path,
        {
            "2024-01-01": [("CVE-2024-0001", 0.1, 0.3)],
            "2024-02-01": [("CVE-2024-0001", 0.4, 0.8)],
        },
    )
    pf = pq.ParquetFile(p)
    assert _epss_row_groups(pf, None, _ns(["2023-06-01"])[0]) == []
    corpus = pd.DataFrame(
        {"cve_id": ["CVE-2024-0001"], "published": pd.to_datetime(["2020-01-01"], utc=True)}
    )
    feat = build_epss_at_publication(corpus, p, snapshot_date="2023-06-01").set_index("cve_id")
    assert feat.loc["CVE-2024-0001", "epss_at_publication_missing"] == 1
    assert feat.loc["CVE-2024-0001", "epss_at_publication"] == 0.0
